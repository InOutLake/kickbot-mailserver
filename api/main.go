package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/emersion/go-imap"
	imapclient "github.com/emersion/go-imap/client"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var (
	botToken        = os.Getenv("TELEGRAM_BOT_TOKEN")
	domain          = os.Getenv("MAIL_DOMAIN")
	mailContainer   = os.Getenv("MAILSERVER_CONTAINER")
	defaultPassword = os.Getenv("DEFAULT_PASSWORD")
	apiKey          = os.Getenv("API_KEY")
	imapServer      = os.Getenv("IMAP_SERVER")
)

func validateEnv() {
	required := []string{"TELEGRAM_BOT_TOKEN", "MAIL_DOMAIN", "MAILSERVER_CONTAINER", "DEFAULT_PASSWORD", "API_KEY", "IMAP_SERVER"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			log.Fatalf("Missing required environment variable: %s", env)
		}
	}
}

type SessionManager struct {
	authorizedUsers sync.Map
}

func (sm *SessionManager) IsAuthorized(chatID int64) bool {
	val, ok := sm.authorizedUsers.Load(chatID)
	return ok && val.(bool)
}

func (sm *SessionManager) Authorize(chatID int64) {
	sm.authorizedUsers.Store(chatID, true)
}

func main() {
	validateEnv()

	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}
	defer dockerCli.Close()

	/* telegram bot */
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatalf("Failed to create Telegram bot: %v", err)
	}
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	sessionMgr := &SessionManager{}

	/* main bot loop */
	for update := range updates {
		if update.Message == nil {
			continue
		}

		chatID := update.Message.Chat.ID
		msgText := update.Message.Text
		args := strings.Fields(msgText)
		command := args[0]

		// Handle /auth command specifically (does not require auth to run)
		if command == "/auth" {
			handleAuth(bot, sessionMgr, update.Message, args)
			continue
		}

		// Middleware: Check Authorization for all other commands
		if !sessionMgr.IsAuthorized(chatID) {
			reply(bot, chatID, "⛔ Unauthorized. Please authenticate using `/auth <YOUR_API_KEY>`")
			continue
		}

		// Command Switch
		switch command {
		case "/start":
			reply(bot, chatID, "Welcome! \nCommands:\n/create <username> - Create new email\n/listen <username> <minutes> - Forward incoming emails")
		case "/create":
			handleCreate(bot, dockerCli, update.Message, args)
		case "/listen":
			handleListen(bot, update.Message, args)
		default:
			reply(bot, chatID, "Unknown command.")
		}
	}
}

/* --- Bot functions --- */
func reply(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleAuth(bot *tgbotapi.BotAPI, sm *SessionManager, msg *tgbotapi.Message, args []string) {
	if len(args) < 2 {
		reply(bot, msg.Chat.ID, "Usage: /auth <API_KEY>")
		return
	}
	if args[1] == apiKey {
		sm.Authorize(msg.Chat.ID)
		reply(bot, msg.Chat.ID, "✅ Authenticated successfully! You can now use bot commands.")
	} else {
		reply(bot, msg.Chat.ID, "❌ Invalid API Key.")
	}
}

func handleCreate(bot *tgbotapi.BotAPI, dockerCli *client.Client, msg *tgbotapi.Message, args []string) {
	if len(args) < 2 {
		reply(bot, msg.Chat.ID, "Usage: /create <username>")
		return
	}
	username := args[1]

	reply(bot, msg.Chat.ID, fmt.Sprintf("⏳ Creating account %s@%s...", username, domain))

	err := createEmailContainerExec(context.Background(), dockerCli, username)
	if err != nil {
		reply(bot, msg.Chat.ID, fmt.Sprintf("❌ Failed: %v", err))
		return
	}

	reply(bot, msg.Chat.ID, fmt.Sprintf("✅ Account created: %s@%s\nPassword: %s", username, domain, defaultPassword))
}

func handleListen(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, args []string) {
	if len(args) < 3 {
		reply(bot, msg.Chat.ID, "Usage: /listen <username> <minutes>")
		return
	}
	username := args[1]
	duration, err := time.ParseDuration(args[2] + "m")
	if err != nil {
		reply(bot, msg.Chat.ID, "Invalid duration. Use integer for minutes (e.g., '10').")
		return
	}

	email := fmt.Sprintf("%s@%s", username, domain)
	reply(bot, msg.Chat.ID, fmt.Sprintf("📡 Listening for new emails on %s for %v...", email, duration))

	go listenForEmails(bot, msg.Chat.ID, username, defaultPassword, duration)
}

/* --- Core Logic --- */

func listenForEmails(bot *tgbotapi.BotAPI, chatID int64, username, password string, duration time.Duration) {
	fullEmail := fmt.Sprintf("%s@%s", username, domain)
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	c, err := imapclient.DialTLS(imapServer, nil)
	if err != nil {
		var err2 error
		c, err2 = imapclient.Dial(imapServer)
		if err2 != nil {
			reply(bot, chatID, fmt.Sprintf("❌ IMAP Connection failed for %s: %v", fullEmail, err))
			return
		}
	}
	defer c.Logout()

	if err := c.Login(fullEmail, password); err != nil {
		reply(bot, chatID, fmt.Sprintf("❌ IMAP Login failed for %s: %v", fullEmail, err))
		return
	}

	mbox, err := c.Select("INBOX", false)
	if err != nil {
		return
	}

	lastSeenSeqNum := mbox.Messages
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			reply(bot, chatID, fmt.Sprintf("🛑 Stopped listening on %s (Time expired)", fullEmail))
			return
		case <-ticker.C:
			mbox, err = c.Select("INBOX", false)
			if err != nil {
				continue
			}

			if mbox.Messages > lastSeenSeqNum {
				seqSet := new(imap.SeqSet)
				seqSet.AddRange(lastSeenSeqNum+1, mbox.Messages)

				section := &imap.BodySectionName{}
				items := []imap.FetchItem{section.FetchItem(), imap.FetchEnvelope}
				messages := make(chan *imap.Message, 10)

				done := make(chan error, 1)
				go func() {
					done <- c.Fetch(seqSet, items, messages)
				}()

				for msg := range messages {
					subject := msg.Envelope.Subject
					from := msg.Envelope.From[0].Address()

					r := msg.GetBody(section)
					if r != nil {
						text := fmt.Sprintf("📧 **New Email for %s**\nFrom: %s\nSubject: %s", username, from, subject)
						reply(bot, chatID, text)
					}
				}

				if err := <-done; err != nil {
					log.Println("Fetch error:", err)
				}

				lastSeenSeqNum = mbox.Messages
			}
		}
	}
}

func createEmailContainerExec(ctx context.Context, cli *client.Client, username string) error {
	email := fmt.Sprintf("%s@%s", username, domain)

	execConfig := container.ExecOptions{
		Cmd:          []string{"setup", "email", "add", email, defaultPassword},
		AttachStdout: true,
		AttachStderr: true,
	}

	idResponse, err := cli.ContainerExecCreate(ctx, mailContainer, execConfig)
	if err != nil {
		return err
	}

	err = cli.ContainerExecStart(ctx, idResponse.ID, container.ExecStartOptions{})
	if err != nil {
		return err
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			inspect, err := cli.ContainerExecInspect(ctx, idResponse.ID)
			if err != nil {
				return err
			}
			if !inspect.Running {
				if inspect.ExitCode != 0 {
					return fmt.Errorf("command failed with exit code %d", inspect.ExitCode)
				}
				return nil
			}
		}
	}
}
