package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

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

	return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
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
