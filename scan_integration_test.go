//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"github.com/willswire/trivy-plugin-zarf/pkg/zarf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestFullIntegration tests against a real zarf package
// Run with: go test -tags=integration -v ./...
func TestFullIntegration(t *testing.T) {
	// Check if zarf is installed
	if _, err := exec.LookPath("zarf"); err != nil {
		t.Fatalf("Zarf not found in PATH, required for this test")
	}

	// Check if trivy is installed
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Fatalf("Trivy not found in PATH, required for this test")
	}

	// Define path for local Zarf package and OCI reference
	ociRef := "oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0"

	// Create a temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "trivy-zarf-test-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a temporary directory for downloading
	downloadDir, err := os.MkdirTemp("", "trivy-zarf-download-*")
	if err != nil {
		t.Fatalf("Failed to create temp download directory: %v", err)
	}
	defer os.RemoveAll(downloadDir)

	// Pull the package from OCI registry
	packageFile, err := zarf.PullZarfPackage(ociRef, downloadDir, true, "")
	if err != nil {
		t.Fatalf("Failed to pull package from OCI registry: %v", err)
	}
	t.Logf("Successfully pulled package to: %s", packageFile)

	// Run the binary with the file reference
	binaryPath := "go"
	args := []string{"run", "main.go", "scan", packageFile}
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s %s", binaryPath, args)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run binary with file reference: %v\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check the output to ensure it contains expected content
	t.Logf("Command stdout:\n%s", stdout.String())
	t.Logf("Command stderr:\n%s", stderr.String())

	expectedOutputs := []string{
		"Package extracted",
		"Found images to scan",
	}

	for _, expected := range expectedOutputs {
		if !bytes.Contains(stderr.Bytes(), []byte(expected)) {
			t.Errorf("Expected output to contain '%s', but it didn't", expected)
		}
	}
}

// TestOCIIntegration tests the OCI reference pulling functionality
// Run with: go test -tags=integration -v ./...
func TestOCIIntegration(t *testing.T) {
	// Check required tools (fail if not available)
	if _, err := exec.LookPath("zarf"); err != nil {
		t.Fatalf("Zarf not found in PATH, required for this test")
	}

	if _, err := exec.LookPath("trivy"); err != nil {
		t.Fatalf("Trivy not found in PATH, required for this test")
	}

	// Use a known Zarf package OCI reference
	ociRef := "oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0"

	// Run the binary with the OCI reference
	binaryPath := "go"
	args := []string{"run", "main.go", "scan", "--skip-signature-validation", ociRef}
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s %s", binaryPath, args)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run binary with OCI reference: %v\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check the output to ensure it contains expected content
	t.Logf("Command stdout:\n%s", stdout.String())
	t.Logf("Command stderr:\n%s", stderr.String())

	expectedOutputs := []string{
		"Package extracted",
		"Found images to scan",
	}

	for _, expected := range expectedOutputs {
		if !bytes.Contains(stderr.Bytes(), []byte(expected)) {
			t.Errorf("Expected output to contain '%s', but it didn't", expected)
		}
	}
}

// TestJSONOutputIntegration tests the JSON output functionality
// Run with: go test -tags=integration -v ./...
func TestJSONOutputIntegration(t *testing.T) {
	// Check required tools (fail if not available)
	if _, err := exec.LookPath("zarf"); err != nil {
		t.Fatalf("Zarf not found in PATH, required for this test")
	}

	if _, err := exec.LookPath("trivy"); err != nil {
		t.Fatalf("Trivy not found in PATH, required for this test")
	}

	// Use a known Zarf package OCI reference
	ociRef := "oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0"

	// Create a temporary output directory
	outputDir, err := os.MkdirTemp("", "trivy-zarf-json-output-*")
	if err != nil {
		t.Fatalf("Failed to create temp output directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	// Run the binary with the JSON output flag
	binaryPath := "go"
	args := []string{"run", "main.go", "scan", "--skip-signature-validation", "--output", outputDir, ociRef}
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s %s", binaryPath, args)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run binary with JSON output: %v\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check the output to ensure it contains expected content
	output := stdout.String()
	t.Logf("Command output:\n%s", output)

	// Verify JSON files were created in the output directory
	files, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("Failed to read output directory: %v", err)
	}

	if len(files) == 0 {
		t.Errorf("No JSON files were created in the output directory")
	}

	// Check if files have .json extension
	jsonCount := 0
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			jsonCount++

			// Verify file contains valid JSON
			jsonPath := filepath.Join(outputDir, file.Name())
			data, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Errorf("Failed to read JSON file %s: %v", jsonPath, err)
				continue
			}

			var jsonData interface{}
			if err := json.Unmarshal(data, &jsonData); err != nil {
				t.Errorf("File %s does not contain valid JSON: %v", jsonPath, err)
			}
		}
	}

	if jsonCount == 0 {
		t.Errorf("No .json files found in the output directory")
	} else {
		t.Logf("Found %d JSON files in the output directory", jsonCount)
	}
}

func TestArchitectureIntegration(t *testing.T) {
	if _, err := exec.LookPath("zarf"); err != nil {
		t.Fatalf("Zarf not found in PATH, required for this test")
	}

	if _, err := exec.LookPath("trivy"); err != nil {
		t.Fatalf("Trivy not found in PATH, required for this test")
	}

	ociRef := "oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0"

	binaryPath := "go"
	args := []string{"run", "main.go", "scan", "--skip-signature-validation", "--arch", "amd64", ociRef}
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s %s", binaryPath, args)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run binary with arch flag: %v\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check the output
	t.Logf("Command stdout:\n%s", stdout.String())
	t.Logf("Command stderr:\n%s", stderr.String())

	// Verify the output contains expected content
	expectedOutputs := []string{
		"Package extracted",
		"Found images to scan",
	}

	for _, expected := range expectedOutputs {
		if !bytes.Contains(stderr.Bytes(), []byte(expected)) {
			t.Errorf("Expected output to contain '%s', but it didn't", expected)
		}
	}
}
