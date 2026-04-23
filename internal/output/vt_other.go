//go:build !windows

package output

// EnableVT is a no-op on non-Windows systems.
func EnableVT() {}
