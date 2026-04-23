package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestNoop_DiscardsEverything(t *testing.T) {
	r := NewNoop()
	r.SetTotal(100)
	for i := 0; i < 1000; i++ {
		r.Tick()
	}
	r.Finish() // must not panic
}

func TestBar_KnownTotal_RendersCount(t *testing.T) {
	var buf bytes.Buffer
	r := NewFor(&buf, "scanning")
	r.SetTotal(5)
	for i := 0; i < 5; i++ {
		r.Tick()
	}
	r.Finish()

	out := buf.String()
	if !strings.Contains(out, "scanning") {
		t.Errorf("description missing: %q", out)
	}
	// The bar throttles renders to 100ms so the only frame we're guaranteed
	// to see is the first one. Assert the total was registered by looking
	// for any "/5" progress marker.
	if !strings.Contains(out, "/5") {
		t.Errorf("expected total 5 in progress render: %q", out)
	}
}

func TestBar_IndeterminateDoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	r := NewFor(&buf, "unknown-total")
	// Skip SetTotal: indeterminate path.
	for i := 0; i < 3; i++ {
		r.Tick()
	}
	r.Finish()
}

// Test both branches of New(): TTY (bar) and non-TTY (noop).
func TestNew_NoTTY_ReturnsNoop(t *testing.T) {
	orig := isTTY
	t.Cleanup(func() { isTTY = orig })
	isTTY = func() bool { return false }

	r := New("scanning", false)
	if _, ok := r.(noop); !ok {
		t.Fatalf("expected noop, got %T", r)
	}
}

func TestNew_TTY_ReturnsBar(t *testing.T) {
	orig := isTTY
	t.Cleanup(func() { isTTY = orig })
	isTTY = func() bool { return true }

	r := New("scanning", false)
	if _, ok := r.(noop); ok {
		t.Fatal("TTY branch should not return noop")
	}
}

func TestNew_Force_BypassesTTYCheck(t *testing.T) {
	orig := isTTY
	t.Cleanup(func() { isTTY = orig })
	isTTY = func() bool { return false }

	r := New("scanning", true)
	if _, ok := r.(noop); ok {
		t.Fatal("force=true must bypass TTY check")
	}
}

func TestBar_ConcurrentTicks(t *testing.T) {
	var buf bytes.Buffer
	r := NewFor(&buf, "parallel")
	r.SetTotal(200)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Tick()
		}()
	}
	wg.Wait()
	r.Finish()
}
