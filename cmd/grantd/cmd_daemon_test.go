package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"grantd/internal/client"
)

func shortSocket(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "s.sock")
}

func TestStatusNotRunning(t *testing.T) {
	sock := shortSocket(t)
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"status", "--socket", sock})
	err := root.Execute()
	if !errors.Is(err, client.ErrNotRunning) {
		t.Fatalf("err = %v, want ErrNotRunning", err)
	}
	if !strings.Contains(err.Error(), sock) || !strings.Contains(err.Error(), "grantd daemon") {
		t.Errorf("message lacks socket path or hint: %v", err)
	}
}

func TestDaemonAndStatusEndToEnd(t *testing.T) {
	useFakeBackends(t)
	sock := shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := newRootCmd()
	d.SetOut(&bytes.Buffer{})
	d.SetErr(&bytes.Buffer{})
	d.SetArgs([]string{"daemon", "--socket", sock})
	done := make(chan error, 1)
	go func() { done <- d.ExecuteContext(ctx) }()

	var out bytes.Buffer
	var err error
	for range 100 {
		root := newRootCmd()
		out.Reset()
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"status", "--socket", sock})
		if err = root.Execute(); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("status never succeeded: %v", err)
	}
	for _, want := range []string{"running (pid " + strconv.Itoa(os.Getpid()) + ")", "socket:       " + sock, "not initialized"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status output lacks %q:\n%s", want, out.String())
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("daemon exit = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Errorf("socket remains after shutdown: %v", err)
	}
}

func TestDaemonRefusesSecondInstance(t *testing.T) {
	useFakeBackends(t)
	sock := shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, sock, nil) }()
	for range 100 {
		if _, err := client.Status(ctx, sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := runDaemon(ctx, sock, nil); err == nil {
		t.Error("second daemon started on a live socket")
	}
	cancel()
	<-done
}

func TestResolveSocket(t *testing.T) {
	if p, err := resolveSocket("/x/y.sock"); err != nil || p != "/x/y.sock" {
		t.Errorf("flag: %q %v", p, err)
	}
	t.Setenv("GRANTD_SOCKET", "/env/z.sock")
	if p, err := resolveSocket(""); err != nil || p != "/env/z.sock" {
		t.Errorf("env: %q %v", p, err)
	}
}
