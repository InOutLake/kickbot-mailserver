package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type Request struct {
	Usernames []string `json:"usernames"`
}

var (
	domain          = os.Getenv("MAIL_DOMAIN")
	mailContainer   = os.Getenv("MAILSERVER_CONTAINER")
	defaultPassword = os.Getenv("DEFAULT_PASSWORD")
	apiKey          = os.Getenv("API_KEY")
)

func createEmail(ctx context.Context, cli *client.Client, username string) error {
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

	resp, err := cli.ContainerExecAttach(ctx, idResponse.ID, container.ExecAttachOptions{})
	if err != nil {
		return err
	}
	defer resp.Close()

	if err := cli.ContainerExecStart(ctx, idResponse.ID, container.ExecStartOptions{}); err != nil {
		return err
	}

	var execInspect container.ExecInspect
	for {
		execInspect, err = cli.ContainerExecInspect(ctx, idResponse.ID)
		if err != nil {
			return fmt.Errorf("failed to inspect exec: %w", err)
		}
		if !execInspect.Running {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	var stdoutBuf bytes.Buffer
	if execInspect.ExitCode != 0 {
		return fmt.Errorf("exec failed with exit code %d (stdout: %q)", execInspect.ExitCode, stdoutBuf.String())
	}

	return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "Authorization header missing"`, http.StatusUnauthorized)
		return
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		http.Error(w, `{"error":"invalid Authorization format (expected 'Bearer <token>')"}`, http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, prefix)
	if token != apiKey {
		http.Error(w, `{"error":"invalid or missing API key"}`, http.StatusForbidden)
		return
	}

	apiClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	defer apiClient.Close()

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	type Result struct {
		Username string `json:"username"`
		Status   string `json:"status"`
		Error    string `json:"error,omitempty"`
	}

	var results []Result

	for _, username := range req.Usernames {
		err := createEmail(context.Background(), apiClient, username)
		if err != nil {
			results = append(results, Result{Username: username, Status: "failed", Error: err.Error()})
		} else {
			results = append(results, Result{Username: username, Status: "created"})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func main() {
	if domain == "" || mailContainer == "" || defaultPassword == "" {
		log.Fatal("Environment variables MAIL_DOMAIN, MAILSERVER_CONTAINER, DEFAULT_PASSWORD must be set")
	}

	http.HandleFunc("/create", handler)
	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
