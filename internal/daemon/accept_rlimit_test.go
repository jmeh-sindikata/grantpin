//go:build darwin || linux

package daemon

import (
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

// With the process out of file descriptors, Accept fails with EMFILE. The
// daemon must stay up and serve the queued client once descriptors are free
// again. This lowers RLIMIT_NOFILE for the whole test process for a moment, so
// it is skipped where the limit cannot be changed or the process already uses
// too many descriptors.
func TestServeSurvivesRealEMFILE(t *testing.T) {
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
		t.Skipf("getrlimit: %v", err)
	}
	const low = 192
	if old.Cur <= low {
		t.Skipf("RLIMIT_NOFILE is already %d", old.Cur)
	}
	logs := &syncBuf{}
	r := start(t, Config{Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: low, Max: old.Max}); err != nil {
		t.Skipf("setrlimit: %v", err)
	}
	var hogs []*os.File
	restore := func() {
		for _, f := range hogs {
			f.Close()
		}
		hogs = nil
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &old)
	}
	defer restore()

	// Use up every descriptor but one...
	for {
		f, err := os.Open(os.DevNull)
		if err != nil {
			break
		}
		hogs = append(hogs, f)
	}
	if len(hogs) < 4 {
		t.Skipf("only %d descriptors to play with", len(hogs))
	}
	// ...free one for the client's own socket (it connects, and the server's
	// accept then has no descriptor to take it with)...
	hogs[len(hogs)-1].Close()
	hogs = hogs[:len(hogs)-1]
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// (On the BSDs, macOS included, the kernel drops a connection whose accept
	// fails with EMFILE; on Linux it stays queued. Either way this client's
	// outcome is not asserted, only that the daemon outlives it.)
	// ...give the server time to hit EMFILE a few times, then free descriptors.
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-r.done:
		t.Fatalf("Serve returned while out of descriptors: %v", err)
	default:
	}
	restore()
	if !strings.Contains(logs.String(), "accept failed; retrying") {
		t.Errorf("accept never failed, so the test proved nothing:\n%s", logs.String())
	}

	_, resp := call(t, r.path, proto.Request{Op: proto.OpStatus})
	if !resp.OK {
		t.Fatalf("status after recovery = %+v", resp)
	}
}
