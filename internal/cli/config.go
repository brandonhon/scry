package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configFlags lists flag names that should be bound to viper keys. Only
// the behaviour-shaping flags are bound.
//
// Deliberate omissions:
//   - positional targets (not flags)
//   - "version", "help", "list-scripts" (control/meta flags)
//   - "sn" (alias for --ping-only; would double-write the same bool)
//   - "verbose" (short count flag -v/-vv; YAML users set the
//     underlying number via a new `verbose: 2` key — but pflag's
//     CountVar doesn't round-trip cleanly through viper.Set, so this
//     is currently a documented gap)
//   - "config" (would be circular)
//
// When adding a new flag in root.go that should be config-loadable,
// append it to this list.
var configFlags = []string{
	"ports", "timeout", "exclude", "concurrency", "max-hosts", "retries",
	"up", "down", "output", "no-color", "ping-only", "no-dns", "banner",
	"no-progress", "script", "script-timeout", "syn", "rate", "adaptive",
	"live",
}

// loadConfig reads ~/.config/scry/config.yaml (or the path in
// --config / $SCRY_CONFIG) and applies its values to any flag that
// wasn't explicitly set on the command line. Flag > env > config file.
// Returns the config path actually read (empty if none was used).
func loadConfig(cmd *cobra.Command, cfgPath string, stderr io.Writer) (string, error) {
	v := viper.New()
	v.SetEnvPrefix("SCRY")
	v.AutomaticEnv()

	explicit := true
	if cfgPath != "" {
		v.SetConfigFile(cfgPath)
	} else if envPath := os.Getenv("SCRY_CONFIG"); envPath != "" {
		v.SetConfigFile(envPath)
	} else {
		path, err := defaultConfigPath()
		if err != nil {
			return "", nil // no default available; silently skip
		}
		v.SetConfigFile(path)
		explicit = false
	}

	if err := v.ReadInConfig(); err != nil {
		// Implicit default: a missing file is expected; silently skip.
		// Explicit --config / SCRY_CONFIG: any read error is fatal.
		// This replaces an earlier Stat+Read pair that had a TOCTOU
		// window between the two syscalls.
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("config %s: %w", v.ConfigFileUsed(), err)
	}

	for _, name := range configFlags {
		f := cmd.Flags().Lookup(name)
		if f == nil || f.Changed {
			continue
		}
		key := name
		if !v.IsSet(key) {
			continue
		}
		// cobra wants the flag's string form; viper gives us the typed
		// value. Converting via fmt is tolerant of int/bool/string/slice.
		raw := v.Get(key)
		if err := setFlagFromConfig(cmd, name, raw); err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: config %s=%v: %v\n", name, raw, err)
		}
	}
	return v.ConfigFileUsed(), nil
}

// setFlagFromConfig applies a raw config value to a cobra flag by its
// name. Supports string, bool, int, duration (as string), string slice,
// and numeric values rendered via fmt.Sprint.
func setFlagFromConfig(cmd *cobra.Command, name string, raw any) error {
	switch val := raw.(type) {
	case []any:
		for _, item := range val {
			if err := cmd.Flags().Set(name, fmt.Sprint(item)); err != nil {
				return err
			}
		}
		return nil
	case []string:
		for _, item := range val {
			if err := cmd.Flags().Set(name, item); err != nil {
				return err
			}
		}
		return nil
	default:
		return cmd.Flags().Set(name, fmt.Sprint(val))
	}
}

// defaultConfigPath returns the platform-appropriate config file
// location. On Unix: ~/.config/scry/config.yaml (respects XDG_CONFIG_HOME).
// On Windows: %APPDATA%\scry\config.yaml.
func defaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "scry", "config.yaml"), nil
}
