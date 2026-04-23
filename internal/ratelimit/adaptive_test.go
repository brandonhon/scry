package ratelimit

import (
	"context"
	"testing"
)

func TestAdaptive_ZeroIsNoop(t *testing.T) {
	a := NewAdaptive(0, 0)
	if err := a.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.ReportProbe(true) // must not panic
}

func TestAdaptive_HighErrRate_HalvesRate(t *testing.T) {
	a := NewAdaptive(8000, 8000)
	// Fill one window with 3% errors.
	for i := 0; i < adaptiveWindow; i++ {
		a.ReportProbe(i < 20) // 20/500 = 4% > 2%
	}
	if got := a.Current(); got >= 8000 {
		t.Fatalf("expected rate < 8000 after high-err window, got %d", got)
	}
	if got := a.Current(); got != 4000 {
		t.Fatalf("expected halving to 4000, got %d", got)
	}
}

func TestAdaptive_LowErrRate_DoublesRate(t *testing.T) {
	a := NewAdaptive(1000, 8000)
	// Fill window with zero errors.
	for i := 0; i < adaptiveWindow; i++ {
		a.ReportProbe(false)
	}
	if got := a.Current(); got != 2000 {
		t.Fatalf("expected doubling to 2000, got %d", got)
	}
}

func TestAdaptive_DoublingCappedAtMax(t *testing.T) {
	a := NewAdaptive(6000, 8000)
	for i := 0; i < adaptiveWindow; i++ {
		a.ReportProbe(false)
	}
	if got := a.Current(); got != 8000 {
		t.Fatalf("expected cap at 8000, got %d", got)
	}
}

func TestAdaptive_HalvingFlooredAtMin(t *testing.T) {
	a := NewAdaptive(100, 8000)
	for i := 0; i < adaptiveWindow; i++ {
		a.ReportProbe(i < 50) // 10% errors
	}
	if got := a.Current(); got < adaptiveMinRate {
		t.Fatalf("rate below floor: %d", got)
	}
}

func TestAdaptive_PartialWindowDoesNotAdjust(t *testing.T) {
	a := NewAdaptive(1000, 8000)
	for i := 0; i < adaptiveWindow/2; i++ {
		a.ReportProbe(true)
	}
	if got := a.Current(); got != 1000 {
		t.Fatalf("rate should be unchanged while window partial, got %d", got)
	}
}
