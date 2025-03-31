package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileAndDirExists(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "trivy-zarf-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test file
	testFile := filepath.Join(tempDir, "testfile.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test fileExists
	if !fileExists(testFile) {
		t.Errorf("fileExists returned false for existing file")
	}

	if fileExists(filepath.Join(tempDir, "nonexistent.txt")) {
		t.Errorf("fileExists returned true for non-existent file")
	}

	// Test dirExists
	if !dirExists(tempDir) {
		t.Errorf("dirExists returned false for existing directory")
	}

	if dirExists(filepath.Join(tempDir, "nonexistent")) {
		t.Errorf("dirExists returned true for non-existent directory")
	}
}

func TestGetImageName(t *testing.T) {
	// Test with org.opencontainers.image.ref.name annotation
	manifest := Manifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:123456789abcdef1234567",
		Size:      1024,
		Annotations: map[string]string{
			"org.opencontainers.image.ref.name": "test-image:latest",
		},
	}

	name := getImageName(manifest)
	if name != "test-image:latest" {
		t.Errorf("getImageName with ref.name annotation returned %s, expected test-image:latest", name)
	}

	// Test with org.opencontainers.image.base.name annotation (no ref.name)
	manifest = Manifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:123456789abcdef1234567",
		Size:      1024,
		Annotations: map[string]string{
			"org.opencontainers.image.base.name": "base-image:latest",
		},
	}

	name = getImageName(manifest)
	if name != "base-image:latest" {
		t.Errorf("getImageName with base.name annotation returned %s, expected base-image:latest", name)
	}

	// Test with both annotations (ref.name should take precedence)
	manifest = Manifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:123456789abcdef1234567",
		Size:      1024,
		Annotations: map[string]string{
			"org.opencontainers.image.ref.name":  "ref-name-image:latest",
			"org.opencontainers.image.base.name": "base-name-image:latest",
		},
	}

	name = getImageName(manifest)
	if name != "ref-name-image:latest" {
		t.Errorf("getImageName with both annotations returned %s, expected ref-name-image:latest", name)
	}

	// Test without annotations but with long enough digest
	manifest = Manifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "sha256:123456789abcdef1234567",
		Size:      1024,
	}

	name = getImageName(manifest)
	expectedPrefix := "123456789abcdef"
	if len(name) < len(expectedPrefix) || name[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("getImageName without annotations returned %s, expected to start with %s", name, expectedPrefix)
	}

	// Test with short digest
	manifest = Manifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    "short-digest",
		Size:      1024,
	}

	name = getImageName(manifest)
	if name != "short-digest" {
		t.Errorf("getImageName with short digest returned %s, expected short-digest", name)
	}
}

func TestCopyFile(t *testing.T) {
	// Create temporary directories
	srcDir, err := os.MkdirTemp("", "trivy-zarf-test-src-*")
	if err != nil {
		t.Fatalf("Failed to create source temp directory: %v", err)
	}
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "trivy-zarf-test-dst-*")
	if err != nil {
		t.Fatalf("Failed to create destination temp directory: %v", err)
	}
	defer os.RemoveAll(dstDir)

	// Create a test file
	testContent := "test content for copy operation"
	srcFile := filepath.Join(srcDir, "testfile.txt")
	if err := os.WriteFile(srcFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Copy the file
	dstFile := filepath.Join(dstDir, "testfile.txt")
	if err := copyFile(srcFile, dstFile); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	// Verify the file was copied correctly
	content, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read copied file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("Copied file content doesn't match. Got %s, expected %s", string(content), testContent)
	}
}

func TestCopyDir(t *testing.T) {
	// Create temporary directories
	srcDir, err := os.MkdirTemp("", "trivy-zarf-test-src-*")
	if err != nil {
		t.Fatalf("Failed to create source temp directory: %v", err)
	}
	defer os.RemoveAll(srcDir)

	dstDir, err := os.MkdirTemp("", "trivy-zarf-test-dst-*")
	if err != nil {
		t.Fatalf("Failed to create destination temp directory: %v", err)
	}
	defer os.RemoveAll(dstDir)

	// Create a nested structure
	subDir := filepath.Join(srcDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create test files
	files := map[string]string{
		filepath.Join(srcDir, "file1.txt"): "content of file 1",
		filepath.Join(subDir, "file2.txt"): "content of file 2",
		filepath.Join(srcDir, "file3.txt"): "content of file 3",
	}

	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", path, err)
		}
	}

	// Copy the directory
	targetDir := filepath.Join(dstDir, "copied")
	if err := copyDir(srcDir, targetDir); err != nil {
		t.Fatalf("copyDir failed: %v", err)
	}

	// Verify the structure and contents
	expectedPaths := []string{
		filepath.Join(targetDir, "file1.txt"),
		filepath.Join(targetDir, "subdir", "file2.txt"),
		filepath.Join(targetDir, "file3.txt"),
	}

	for i, path := range expectedPaths {
		if !fileExists(path) {
			t.Errorf("Expected file %s doesn't exist", path)
			continue
		}

		origPath := ""
		switch i {
		case 0:
			origPath = filepath.Join(srcDir, "file1.txt")
		case 1:
			origPath = filepath.Join(subDir, "file2.txt")
		case 2:
			origPath = filepath.Join(srcDir, "file3.txt")
		}

		origContent, _ := os.ReadFile(origPath)
		copiedContent, _ := os.ReadFile(path)
		if string(origContent) != string(copiedContent) {
			t.Errorf("Content mismatch for %s", path)
		}
	}
}

func TestSanitizeFilename(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"docker.io/library/nginx:latest", "docker_io_library_nginx_latest"},
		{"registry.example.com/app:1.0.0", "registry_example_com_app_1_0_0"},
		{"name/with:colon", "name_with_colon"},
		{"name with spaces", "name_with_spaces"},
		{"name/with/slashes", "name_with_slashes"},
		{"name.with.dots", "name_with_dots"},
		{"name_with_underscores", "name_with_underscores"},
		{"name-with-dashes", "name-with-dashes"},
		{"mixed@chars:here!", "mixed_chars_here"},
		{"///multiple///slashes///", "multiple_slashes"},
		{"  leading and trailing spaces  ", "leading_and_trailing_spaces"},
		{"", "unknown_image"}, // Empty string should get default name
		{"__lots__of__underscores__", "lots_of_underscores"},
	}

	for _, tc := range testCases {
		result := sanitizeFilename(tc.input)
		if result != tc.expected {
			t.Errorf("sanitizeFilename(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}
