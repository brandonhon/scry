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
// the behaviour-shaping flags are bound; positional targets, version,
// help, and list-scripts are not.
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

	if cfgPath != "" {
		v.SetConfigFile(cfgPath)
	} else if envPath := os.Getenv("SCRY_CONFIG"); envPath != "" {
		v.SetConfigFile(envPath)
	} else {
		path, err := defaultConfigPath()
		if err != nil {
			return "", nil // no default available; silently skip
		}
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return "", nil // nothing to load
		}
		v.SetConfigFile(path)
	}

	if err := v.ReadInConfig(); err != nil {
		// Explicit --config / SCRY_CONFIG must succeed; implicit default
		// that goes missing mid-read is an error too (we stat'd it).
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
			fmt.Fprintf(stderr, "warning: config %s=%v: %v\n", name, raw, err)
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
