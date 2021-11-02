package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/sessions/v1"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/nerdctl/pkg/idgen"
	"github.com/containerd/nerdctl/pkg/platformutil"
	"github.com/creack/pty"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	userKey  = "DACSUSER"
	tokenKey = "DACSTOKEN"
	uuidKey  = "DACSUUID"
)

func newSessionCommand() *cobra.Command {
	var sessionCommand = &cobra.Command{
		Use:           "session",
		Short:         "create a new terminal session for user.",
		RunE:          sessionAction,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	sessionCommand.Flags().StringP("username", "u", "", "dacs username")
	sessionCommand.Flags().StringP("password", "p", "", "dacs username's password")
	// #region platform flags
	sessionCommand.Flags().String("platform", "", "Set platform (e.g. \"amd64\", \"arm64\")") // not a slice, and there is no --all-platforms
	return sessionCommand
}

func sessionAction(cmd *cobra.Command, args []string) error {
	var clientOpts []containerd.ClientOpt
	platform, err := cmd.Flags().GetString("platform")
	if err != nil {
		return err
	}
	if platform != "" {
		if canExec, canExecErr := platformutil.CanExecProbably(platform); !canExec {
			warn := fmt.Sprintf("Platform %q seems incompatible with the host platform %q. If you see \"exec format error\", see https://github.com/containerd/nerdctl/blob/master/docs/multi-platform.md",
				platform, platforms.DefaultString())
			if canExecErr != nil {
				logrus.WithError(canExecErr).Warn(warn)
			} else {
				logrus.Warn(warn)
			}
		}
		platformParsed, err := platforms.Parse(platform)
		if err != nil {
			return err
		}
		platformM := platforms.Only(platformParsed)
		clientOpts = append(clientOpts, containerd.WithDefaultPlatform(platformM))
	}

	client, ctx, cancel, err := newClient(cmd, clientOpts...)
	if err != nil {
		return err
	}
	defer cancel()
	username, err := cmd.Flags().GetString("username")
	if err != nil {
		return err
	}
	password, err := cmd.Flags().GetString("password")
	if err != nil {
		return err
	}
	req := &sessions.AuthRequest{
		User: &sessions.UserInfo{
			Username: username,
			Password: password,
		},
	}
	resp, err := client.SessionService().Auth(ctx, req)
	if err != nil {
		return err
	}
	token := resp.Token
	if err := terminal(username, token, ctx, client.SessionService()); err != nil {
		return err
	}
	return nil
}

// only support linux
func terminal(username, token string, ctx context.Context, client sessions.SessionsClient) error {
	// Create arbitrary commasnd.
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "bash"
	}
	randomUUID := idgen.GenerateID()[:24]
	envs := os.Environ()
	envs = append(envs, fmt.Sprintf("%s=%s", userKey, username))
	envs = append(envs, fmt.Sprintf("%s=%s", tokenKey, token))
	envs = append(envs, fmt.Sprintf("%s=%s", uuidKey, randomUUID))
	c := exec.Command(shell)
	c.Env = envs

	// Start the command with a pty.
	ptmx, err := pty.Start(c)
	if err != nil {
		return err
	}
	// Make sure to close the pty at the end.
	defer func() { _ = ptmx.Close() }() // Best effort.

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
				fmt.Printf("error resizing pty: %s", err)
			}
		}
	}()
	ch <- syscall.SIGWINCH                        // Initial resize.
	defer func() { signal.Stop(ch); close(ch) }() // Cleanup signals when done.

	// Set stdin in raw mode.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.

	// register session id
	sessionID := fmt.Sprintf("%d_%s", c.Process.Pid, randomUUID)
	req := &sessions.RegisterSessionRequest{
		Session: &sessions.Session{
			ID:       sessionID,
			Username: username,
			Token:    token,
		},
		Action: sessions.ACTION_REGISTER,
	}

	if _, err := client.RegisterSession(ctx, req); err != nil {
		return err
	}

	fmt.Print("success login, session id ", sessionID)
	// Copy stdin to the pty and the pty to stdout.
	// NOTE: The goroutine will keep reading until the next keystroke before returning.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()

	_, _ = io.Copy(os.Stdout, ptmx)

	req.Action = sessions.ACTION_UNREGISTER
	if _, err := client.RegisterSession(ctx, req); err != nil {
		return err
	}
	fmt.Print("exit session.")
	return nil
}
