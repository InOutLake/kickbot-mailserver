package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/emersion/go-imap"
	imapclient "github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var (
	botToken        = os.Getenv("TELEGRAM_BOT_TOKEN")
	domain          = os.Getenv("MAIL_DOMAIN")
	mailContainer   = os.Getenv("MAILSERVER_CONTAINER")
	defaultPassword = os.Getenv("DEFAULT_PASSWORD")
	apiKey          = os.Getenv("API_KEY")
	imapServer      = os.Getenv("IMAP_SERVER")
	localedir       = os.Getenv("LOCALE_DIR")
)

const (
	MsgGreeting             = "greeting"
	MsgAuthUsage            = "auth_usage"
	MsgAuthSuccess          = "auth_success"
	MsgAuthFail             = "auth_invalid"
	MsgUnauthorized         = "unauthorized"
	MsgUnknownCommand       = "unknown_command"
	MsgChangeLocaleUsage    = "change_locale_usage"
	MsgChangeLocaleSuccess  = "change_locale_success"
	MsgChangeLocaleFail     = "change_locale_fail"
	MsgCreateUsage          = "create_usage"
	MsgCreateSuccess        = "create_success"
	MsgCreateFailed         = "create_failed"
	MsgListenUsage          = "listen_usage"
	MsgListenStart          = "listen_start"
	MsgListenStopped        = "listen_stopped"
	MsgEmailFromat          = "email_message"
	MsgClearUsage           = "clear_usage"
	MsgClearSuccess         = "clear_success"
	MsgImapConnectionFailed = "imap_connection_failed"
	MsgImapLoginFailed      = "imap_login_failed"
	MsgReadInboxFailed      = "read_inbox_failed"
	MsgFetchFailed          = "fetch_failed"
	MsgTruncated            = "truncated"
	MsgNoTextBody           = "no_text_body"
	MsgEmailFormat          = "email_format"
	MsgCheckProgress        = "check_progress"
	MsgFoundNothing         = "found_nothing"
)

/* NOTE: don't want to bother passing it here and there, so use global variable */
var tStore = InitTranslationStore(localedir)

func ValidateEnv() {
	required := []string{"TELEGRAM_BOT_TOKEN", "MAIL_DOMAIN", "MAILSERVER_CONTAINER", "DEFAULT_PASSWORD", "API_KEY", "IMAP_SERVER", "LOCALE_DIR"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			log.Fatalf("Missing required environment variable: %s", env)
		}
	}
}

func InitTranslationStore(dir string) *TranslationStore {
	store := &TranslationStore{
		translations: make(map[string]map[string]string),
	}
	store.loadTranslations(dir)
	return store
}

type UserSession struct {
	ChatID          int64
	Authorized      bool
	ListeningTo     []string
	ListeningCancel func()
	Language        string
}

func (user *UserSession) Authorize() {
	user.Authorized = true
}

func (user *UserSession) ListenTo(username string) {
	if slices.Contains(user.ListeningTo, username) {
		return
	}
	user.ListeningTo = append(user.ListeningTo, username)
}

type SessionManager struct {
	sessions sync.Map
}

type TranslationStore struct {
	translations map[string]map[string]string
	mu           sync.RWMutex
}

func (ts *TranslationStore) loadTranslations(dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("Failed to read translation directory %s: %v", dir, err)
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".json" {
			langCode := strings.TrimSuffix(file.Name(), ".json")
			filePath := filepath.Join(dir, file.Name())

			data, err := os.ReadFile(filePath)
			if err != nil {
				log.Printf("Warning: Failed to read %s: %v", filePath, err)
				continue
			}

			var messages map[string]string
			if err := json.Unmarshal(data, &messages); err != nil {
				log.Printf("Warning: Failed to parse JSON in %s: %v", filePath, err)
				continue
			}

			ts.translations[langCode] = messages
			log.Printf("Loaded translations for language: %s", langCode)
		}
	}

	if _, ok := ts.translations["en"]; !ok {
		log.Fatal("Error: Default 'en' translation file (en.json) is missing.")
	}
}

func (ts *TranslationStore) GetMessage(langCode, key string, args ...any) string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if msgs, ok := ts.translations[langCode]; ok {
		if msg, ok := msgs[key]; ok {
			return fmt.Sprintf(msg, args...)
		}
	}

	if msgs, ok := ts.translations["en"]; ok {
		if msg, ok := msgs[key]; ok {
			if langCode != "en" {
				log.Printf("Warning: Missing translation key '%s' in language '%s'. Falling back to 'en'.", key, langCode)
			}
			return fmt.Sprintf(msg, args...)
		}
	}

	log.Printf("Error: Translation key '%s' missing in all loaded languages.", key)
	return fmt.Sprintf("Oh no! Translation missing: %s", key)
}

func (ts *TranslationStore) GetT(session *UserSession, key string, args ...any) string {
	langCode := session.Language
	return ts.GetMessage(langCode, key, args)
}

func InitSessionManager() *SessionManager {
	return &SessionManager{}
}

func (sm *SessionManager) GetSession(chatID int64) *UserSession {
	if session, ok := sm.sessions.Load(chatID); ok {
		return session.(*UserSession)
	} else {
		newSession := &UserSession{
			ChatID:      chatID,
			Authorized:  false,
			ListeningTo: []string{},
			Language:    "en",
		}
		sm.sessions.Store(chatID, newSession)
		return newSession
	}
}

func (sm *SessionManager) IsAuthorized(chatID int64) bool {
	session := sm.GetSession(chatID)
	return session.Authorized
}

func SetupLogging() {
	log.SetFlags(log.Ldate | log.Ltime)
}

func InitTelegramBot() (*tgbotapi.BotAPI, tgbotapi.UpdatesChannel) {
	log.Printf("Attempting bot authorization...")
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatalf("Failed to create Telegram bot: %v\n", err)
	}
	log.Printf("Authorized on account %s\n", bot.Self.UserName)
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)
	return bot, updates
}

func InitDockerCli() (*client.Client, func()) {
	log.Printf("Connecting to docker... ")
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v\n", err)
	}
	cleanup := func() {
		log.Println("Closing Docker client connection.")
		if err := dockerCli.Close(); err != nil {
			log.Printf("Error closing docker connection")
		}
	}
	return dockerCli, cleanup
}

func main() {
	/* inits */
	ValidateEnv()
	SetupLogging()
	sessionManager := InitSessionManager()
	bot, updates := InitTelegramBot()
	dockerCli, dockerCleanup := InitDockerCli()
	defer dockerCleanup()

	/* main bot loop */
	for update := range updates {
		if update.Message == nil {
			continue
		}

		chatID := update.Message.Chat.ID
		user := sessionManager.GetSession(chatID)
		msgText := update.Message.Text
		args := strings.Fields(msgText)
		command := args[0]

		if command == "/auth" {
			handleAuth(bot, user, args)
			continue
		}

		if command == "/start" {
			handleGreeting(bot, user)
		}

		if !sessionManager.IsAuthorized(chatID) {
			replyByKey(bot, user, MsgUnauthorized, true)
			continue
		}

		switch command {
		case "/create":
			handleCreate(bot, dockerCli, user, args)
		case "/listen":
			handleListen(bot, user, args)
		case "/check":
			handleCheck(bot, user, true)
		case "/clear":
			handleClear(bot, user, args)
		case "/language":
			handleChangeLanguage(bot, user, args)
		default:
			replyByKey(bot, user, MsgUnknownCommand, true)
		}
	}
}

/* --- Bot functions --- */
func reply(bot *tgbotapi.BotAPI, user *UserSession, text string, md bool) {
	msg := tgbotapi.NewMessage(user.ChatID, text)
	if md {
		msg.ParseMode = "Markdown"
	}
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending message: %v", err)
	}
}

func replyByKey(bot *tgbotapi.BotAPI, user *UserSession, key string, md bool) {
	msg := tStore.GetT(user, key)
	reply(bot, user, msg, md)
}

func handleGreeting(bot *tgbotapi.BotAPI, user *UserSession) {
	replyByKey(bot, user, MsgGreeting, true)
}

func handleChangeLanguage(bot *tgbotapi.BotAPI, user *UserSession, args []string) {
	if len(args) == 2 {
		for locale := range tStore.translations {
			if locale == args[1] {
				user.Language = args[1]
				replyByKey(bot, user, MsgChangeLocaleSuccess, true)
				return
			}
		}
		replyByKey(bot, user, MsgChangeLocaleFail, true)
	}
	msg := tStore.GetT(user, MsgChangeLocaleUsage)
	reply(bot, user, msg, true)
}

func handleAuth(bot *tgbotapi.BotAPI, user *UserSession, args []string) {
	if len(args) < 2 {
		replyByKey(bot, user, MsgAuthUsage, true)
		return
	}
	if args[1] == apiKey {
		user.Authorize()
		replyByKey(bot, user, MsgAuthSuccess, true)
	} else {
		replyByKey(bot, user, MsgAuthFail, true)
	}
}

func handleCreate(bot *tgbotapi.BotAPI, dockerCli *client.Client, user *UserSession, args []string) {
	if len(args) < 2 {
		replyByKey(bot, user, MsgCreateUsage, true)
		return
	}

	username := args[1]
	err := createEmailContainerExec(context.Background(), dockerCli, username)
	if err != nil {
		replyByKey(bot, user, MsgCreateFailed, true)
		return
	}
	user.ListenTo(username)
	replyByKey(bot, user, MsgCreateSuccess, true)
}

func handleListen(bot *tgbotapi.BotAPI, user *UserSession, args []string) {
	if len(args) > 2 {
		replyByKey(bot, user, MsgListenUsage, true)
	}
	if len(args) == 2 {
		username := args[1]
		user.ListenTo(username)
	}

	message := tStore.GetT(user, MsgListenStart)
	message = fmt.Sprintf(message+"\n - %s", strings.Join(user.ListeningTo, "\n - "))
	reply(bot, user, message, true)

	go listenForEmails(bot, user)
}

func handleClear(bot *tgbotapi.BotAPI, user *UserSession, args []string) {
	if len(args) != 1 {
		replyByKey(bot, user, MsgClearUsage, true)
		return
	}
	user.ListeningTo = []string{}
	replyByKey(bot, user, MsgClearSuccess, true)
}

/* --- core Logic --- */
func listenForEmails(bot *tgbotapi.BotAPI, user *UserSession) {
	timeout, _ := time.ParseDuration("20m")
	if user.ListeningCancel != nil {
		user.ListeningCancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	user.ListeningCancel = cancel
	defer cancel()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			handleCheck(bot, user, false)
		}
	}
}

func establishConnecion(bot *tgbotapi.BotAPI, user *UserSession, username string) (*imapclient.Client, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	c, err := imapclient.DialTLS(imapServer, tlsConfig)
	if err != nil {
		var err2 error
		c, err2 = imapclient.Dial(imapServer)
		if err2 != nil {
			log.Printf("Connetction failed for: %v\t cause %v", user, err)
			replyByKey(bot, user, MsgImapConnectionFailed, true)
			return nil, err
		}
	}
	fullEmail := fmt.Sprintf("%s@%s", username, domain)
	if err := c.Login(fullEmail, defaultPassword); err != nil {
		log.Printf("Connetction failed for: %v\t as %s\t cause %v", user, fullEmail, err)
		return nil, err
	}
	return c, nil
}

func checkNewEmails(c *imapclient.Client) ([]uint32, error) {
	_, err := c.Select("INBOX", false)
	if err != nil {
		return nil, err
	}
	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{imap.SeenFlag}
	uids, err := c.Search(criteria)
	if err != nil {
		return nil, err
	}
	return uids, nil
}

func fetchMessages(c *imapclient.Client, uids []uint32) (chan *imap.Message, *imap.BodySectionName, error) {
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uids...)

	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem(), imap.FetchEnvelope}
	messages := make(chan *imap.Message, len(uids)+10)
	if err := c.Fetch(seqSet, items, messages); err != nil {
		return nil, nil, err
	}
	return messages, section, nil
}

func composeMessage(user *UserSession, username string, msg *imap.Message, section *imap.BodySectionName) (string, error) {
	subject := msg.Envelope.Subject
	from := msg.Envelope.From[0].Address()

	r := msg.GetBody(section)
	if r == nil {
		return "", errors.New("NoBody")
	}

	mr, err := mail.CreateReader(r)
	if err != nil {
		log.Printf("Failed to create mail reader: %v", err)
		return "", err
	}

	var bodyText string

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Printf("Error reading email part: %v", err)
			break
		}

		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			contentType, _, _ := h.ContentType()

			if contentType == "text/plain" || (contentType == "text/html" && bodyText == "") {
				b, _ := io.ReadAll(p.Body)
				bodyText = string(b)
			}
		}
	}

	if bodyText == "" {
		bodyText = tStore.GetT(user, MsgNoTextBody)
	}

	if len(bodyText) > 3000 {
		bodyText = bodyText[:3000] + tStore.GetT(user, MsgTruncated)
	}

	text := tStore.GetT(user, MsgEmailFormat)
	text = fmt.Sprintf(text, username, from, subject, bodyText)
	return text, nil
}

func handleCheck(bot *tgbotapi.BotAPI, user *UserSession, verbose bool) {
	found := false
	if verbose {
		replyByKey(bot, user, MsgCheckProgress, true)
	}
	for _, username := range user.ListeningTo {
		func(targetUser string) {
			c, err := establishConnecion(bot, user, targetUser)
			if err != nil {
				replyByKey(bot, user, MsgImapLoginFailed, true)
				return
			}
			defer c.Logout()

			uids, err := checkNewEmails(c)
			if err != nil {
				replyByKey(bot, user, MsgReadInboxFailed, true)
				return
			}

			if len(uids) > 0 {
				messages, section, err := fetchMessages(c, uids)
				if err != nil {
					replyByKey(bot, user, MsgFetchFailed, true)
					return
				}

				for msg := range messages {
					text, err := composeMessage(user, username, msg, section)
					if err != nil {
						log.Printf("Failed to compose message: %v", err)
						continue
					}
					reply(bot, user, text, false)
					found = true
				}
			}
		}(username)
	}
	if verbose && !found {
		replyByKey(bot, user, MsgFoundNothing, true)
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
