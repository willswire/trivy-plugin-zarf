//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestLocalFileIntegration tests against a real zarf package
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
	packageFile, err := pullZarfPackage(ociRef, downloadDir, true)
	if err != nil {
		t.Fatalf("Failed to pull package from OCI registry: %v", err)
	}
	t.Logf("Successfully pulled package to: %s", packageFile)

	// Build the binary if it doesn't exist
	binaryPath := "./trivy-plugin-zarf"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		cmd := exec.Command("go", "build")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to build binary: %v, stderr: %s", err, stderr.String())
		}
	}

	// Run the binary with the file reference
	cmd := exec.Command(binaryPath, packageFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s %s", binaryPath, packageFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run binary with file reference: %v\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check the output to ensure it contains expected content
	output := stdout.String()
	t.Logf("Command output:\n%s", output)

	expectedOutputs := []string{
		"Package extracted to",
		"Found 1 images to scan",
	}

	for _, expected := range expectedOutputs {
		if !bytes.Contains(stdout.Bytes(), []byte(expected)) {
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

	// Build the binary if it doesn't exist
	binaryPath := "./trivy-plugin-zarf"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		cmd := exec.Command("go", "build")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to build binary: %v, stderr: %s", err, stderr.String())
		}
	}

	// Run the binary with the OCI reference
	cmd := exec.Command(binaryPath, "--skip-signature-validation", ociRef)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s %s", binaryPath, ociRef)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run binary with OCI reference: %v\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check the output to ensure it contains expected content
	output := stdout.String()
	t.Logf("Command output:\n%s", output)

	expectedOutputs := []string{
		"Package extracted to",
		"Found 1 images to scan",
	}

	for _, expected := range expectedOutputs {
		if !bytes.Contains(stdout.Bytes(), []byte(expected)) {
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

	// Build the binary if it doesn't exist
	binaryPath := "./trivy-plugin-zarf"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		cmd := exec.Command("go", "build")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to build binary: %v, stderr: %s", err, stderr.String())
		}
	}

	// Create a temporary output directory
	outputDir, err := os.MkdirTemp("", "trivy-zarf-json-output-*")
	if err != nil {
		t.Fatalf("Failed to create temp output directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	// Run the binary with the JSON output flag
	cmd := exec.Command(binaryPath, "--skip-signature-validation", "--output", outputDir, ociRef)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: %s --output %s %s", binaryPath, outputDir, ociRef)
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
