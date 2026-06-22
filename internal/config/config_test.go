package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoad_MissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("expected default config, got %+v", cfg)
	}
}

func TestLoad_ParsesFullFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "warden.yaml")
	content := `
version: "1.0"
policies:
  security:
    allow_network_ingress: false
    forbidden_packages:
      - "unsafe-eval"
      - "crypto-miner"
    max_file_deletions: 5
  infrastructure:
    allowed_aws_regions: ["us-east-1", "eu-west-1"]
    prevent_destructive_changes: true
sandbox:
  enabled: true
  image: "python:3.12-slim"
  timeout_seconds: 15
  memory_limit_mb: 256
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Policies.Security.MaxFileDeletions != 5 {
		t.Errorf("MaxFileDeletions = %d, want 5", cfg.Policies.Security.MaxFileDeletions)
	}
	wantPkgs := []string{"unsafe-eval", "crypto-miner"}
	if !reflect.DeepEqual(cfg.Policies.Security.ForbiddenPackages, wantPkgs) {
		t.Errorf("ForbiddenPackages = %v, want %v", cfg.Policies.Security.ForbiddenPackages, wantPkgs)
	}
	if !cfg.Policies.Infrastructure.PreventDestructiveChanges {
		t.Errorf("PreventDestructiveChanges = false, want true")
	}
	if cfg.Sandbox.TimeoutSeconds != 15 {
		t.Errorf("Sandbox.TimeoutSeconds = %d, want 15", cfg.Sandbox.TimeoutSeconds)
	}
	if cfg.Sandbox.MemoryLimitMB != 256 {
		t.Errorf("Sandbox.MemoryLimitMB = %d, want 256", cfg.Sandbox.MemoryLimitMB)
	}
}

func TestValidate_RejectsNegativeMaxFileDeletions(t *testing.T) {
	cfg := Default()
	cfg.Policies.Security.MaxFileDeletions = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative MaxFileDeletions, got nil")
	}
}

func TestValidate_RejectsEnabledSandboxWithoutImage(t *testing.T) {
	cfg := Default()
	cfg.Sandbox.Image = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty sandbox image, got nil")
	}
}

func TestValidate_RejectsZeroTimeout(t *testing.T) {
	cfg := Default()
	cfg.Sandbox.TimeoutSeconds = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero timeout, got nil")
	}
}
