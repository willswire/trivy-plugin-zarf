//go:build integration
// +build integration

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestFullIntegration tests the full plugin functionality with a real Zarf package
// Run with: go test -tags=integration -v ./...
func TestFullIntegration(t *testing.T) {
	skipIfNoZarf(t)
	skipIfNoTrivy(t)
	
	// Skip if running in CI or if the Zarf package doesn't exist
	zarfPackagePath := "zarf-package-dos-games-arm64-1.2.0.tar.zst"
	if _, err := os.Stat(zarfPackagePath); os.IsNotExist(err) || isCI() {
		t.Skip("Skipping full integration test - Zarf package not available or running in CI")
	}
	
	// Get the absolute path to the Zarf package
	absPath, err := filepath.Abs(zarfPackagePath)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}
	
	// Build the binary if it doesn't exist
	binaryPath := filepath.Join(".", "trivy-plugin-zarf")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		cmd := exec.Command("go", "build", "-o", binaryPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to build binary: %v, stderr: %s", err, stderr.String())
		}
	}
	
	// Run the binary
	cmd := exec.Command(binaryPath, absPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	t.Logf("Running: %s %s", binaryPath, absPath)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run binary: %v\nStdout: %s\nStderr: %s", 
			err, stdout.String(), stderr.String())
	}
	
	// Check the output to ensure it contains expected content
	output := stdout.String()
	t.Logf("Command output:\n%s", output)
	
	expectedOutputs := []string{
		"Extracting Zarf package",
		"Found",
		"images to scan",
		"Scanning image",
	}
	
	for _, expected := range expectedOutputs {
		if !bytes.Contains(stdout.Bytes(), []byte(expected)) {
			t.Errorf("Expected output to contain '%s', but it didn't", expected)
		}
	}
}