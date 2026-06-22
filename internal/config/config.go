// Package config loads and validates the warden.yaml policy file that
// drives both the static analyzer and the policy admission phase.
package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// SecurityPolicy controls Phase 1 (static analysis) thresholds.
type SecurityPolicy struct {
	AllowNetworkIngress bool     `yaml:"allow_network_ingress"`
	ForbiddenPackages   []string `yaml:"forbidden_packages"`
	MaxFileDeletions    int      `yaml:"max_file_deletions"`
}

// InfrastructurePolicy controls Phase 3 (policy admission) thresholds for
// infrastructure-as-code changes.
type InfrastructurePolicy struct {
	AllowedAWSRegions         []string `yaml:"allowed_aws_regions"`
	PreventDestructiveChanges bool     `yaml:"prevent_destructive_changes"`
}

// Policies is the top-level set of rule groups.
type Policies struct {
	Security       SecurityPolicy        `yaml:"security"`
	Infrastructure InfrastructurePolicy   `yaml:"infrastructure"`
}

// Config is the root structure of warden.yaml.
type Config struct {
	Version  string   `yaml:"version"`
	Policies Policies `yaml:"policies"`

	// Sandbox controls Phase 2 runtime behavior. Not yet part of the
	// documented warden.yaml schema in the README, so it ships with safe
	// defaults and can be overridden via environment variables (see
	// internal/config/env.go).
	Sandbox SandboxConfig `yaml:"sandbox"`
}

// SandboxConfig configures the Docker-based dynamic execution phase.
type SandboxConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Image          string `yaml:"image"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	MemoryLimitMB  int64  `yaml:"memory_limit_mb"`
}

// Default returns a conservative built-in configuration used when no
// warden.yaml is present, so the engine never starts "open by default".
func Default() *Config {
	return &Config{
		Version: "1.0",
		Policies: Policies{
			Security: SecurityPolicy{
				AllowNetworkIngress: false,
				ForbiddenPackages:   []string{"unsafe-eval", "crypto-miner"},
				MaxFileDeletions:    3,
			},
			Infrastructure: InfrastructurePolicy{
				AllowedAWSRegions:         []string{"us-east-1", "eu-west-1"},
				PreventDestructiveChanges: true,
			},
		},
		Sandbox: SandboxConfig{
			Enabled:        true,
			Image:          "python:3.12-slim",
			TimeoutSeconds: 10,
			MemoryLimitMB:  128,
		},
	}
}

// Load reads and parses a warden.yaml file at the given path. If the file
// does not exist, it returns Default() rather than erroring, so a fresh
// `agentwarden` checkout works out of the box.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	// Unmarshal on top of the defaults so partial files still get sane
	// fallback values for anything they omit.
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}

	return cfg, nil
}

// Validate performs basic sanity checks so misconfiguration fails fast at
// startup instead of silently no-opping a security control.
func (c *Config) Validate() error {
	if c.Policies.Security.MaxFileDeletions < 0 {
		return fmt.Errorf("policies.security.max_file_deletions must be >= 0")
	}
	if c.Sandbox.Enabled {
		if c.Sandbox.Image == "" {
			return fmt.Errorf("sandbox.image must be set when sandbox.enabled is true")
		}
		if c.Sandbox.TimeoutSeconds <= 0 {
			return fmt.Errorf("sandbox.timeout_seconds must be > 0")
		}
	}
	return nil
}
