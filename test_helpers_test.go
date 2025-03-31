package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// skipIfNoZarf skips the test if zarf is not installed
func skipIfNoZarf(t *testing.T) {
	if _, err := exec.LookPath("zarf"); err != nil {
		t.Skip("Zarf not found in PATH, skipping test")
	}
}

// skipIfNoTrivy skips the test if trivy is not installed
func skipIfNoTrivy(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("Trivy not found in PATH, skipping test")
	}
}

// createMockZarfPackage creates a mock Zarf package structure for testing
func createMockZarfPackage(t *testing.T) string {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "trivy-zarf-mock-package-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create the directory structure
	ociDir := filepath.Join(tempDir, "images")
	if err := os.MkdirAll(ociDir, 0755); err != nil {
		t.Fatalf("Failed to create OCI directory: %v", err)
	}

	// Create blobs directory
	blobsDir := filepath.Join(ociDir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		t.Fatalf("Failed to create blobs directory: %v", err)
	}

	// Create mock OCI layout file
	ociLayoutFile := filepath.Join(ociDir, "oci-layout")
	ociLayoutContent := `{"imageLayoutVersion": "1.0.0"}`
	if err := os.WriteFile(ociLayoutFile, []byte(ociLayoutContent), 0644); err != nil {
		t.Fatalf("Failed to create oci-layout file: %v", err)
	}

	return tempDir
}

// commandExists checks if a command exists in the system's PATH
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// isCI returns true if the test is running in a CI environment
func isCI() bool {
	// Common CI environment variables
	ciVars := []string{
		"CI",
		"TRAVIS",
		"CIRCLECI",
		"GITHUB_ACTIONS",
		"GITLAB_CI",
		"JENKINS_URL",
	}

	for _, v := range ciVars {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

// getTestDataPath returns the path to the test data directory
func getTestDataPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata")
}