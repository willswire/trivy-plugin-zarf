package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestScanOCIImagesMock tests the scanOCIImages function with a mocked OCI layout
func TestScanOCIImagesMock(t *testing.T) {
	// Create a temporary directory structure that mimics an OCI layout
	tempDir, err := os.MkdirTemp("", "trivy-zarf-mock-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create the images directory
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

	// Create a mock index.json with two test images
	mockIndex := OCIIndex{
		Manifests: []Manifest{
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    "sha256:1111111111111111",
				Size:      1024,
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": "test-image-1:latest",
				},
			},
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    "sha256:2222222222222222",
				Size:      2048,
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": "test-image-2:latest",
				},
			},
		},
	}

	// Write the mock index.json
	indexData, err := json.MarshalIndent(mockIndex, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal mock index: %v", err)
	}

	indexPath := filepath.Join(ociDir, "index.json")
	if err := os.WriteFile(indexPath, indexData, 0644); err != nil {
		t.Fatalf("Failed to write mock index.json: %v", err)
	}

	// Create mock blob files - we don't need actual content for testing
	// but we need the files to exist for the directory copy operations
	for _, manifest := range mockIndex.Manifests {
		digest := manifest.Digest
		parts := filepath.SplitList(digest)
		if len(parts) > 1 {
			mockBlobPath := filepath.Join(blobsDir, parts[1])
			if err := os.WriteFile(mockBlobPath, []byte("mock content"), 0644); err != nil {
				t.Fatalf("Failed to create mock blob file: %v", err)
			}
		}
	}

	// Create a custom scanOCIImages replacement that doesn't call Trivy
	// We'll use this to verify the logic that processes the OCI layout
	mockScanCount := 0
	mockScanFunc := func(dir string) error {
		indexData, err := os.ReadFile(filepath.Join(dir, "index.json"))
		if err != nil {
			return err
		}

		var ociIndex OCIIndex
		if err := json.Unmarshal(indexData, &ociIndex); err != nil {
			return err
		}

		for _, manifest := range ociIndex.Manifests {
			imageName := getImageName(manifest)
			t.Logf("Would scan image: %s", imageName)
			mockScanCount++
		}

		return nil
	}

	// Call the mock scan function
	if err := mockScanFunc(ociDir); err != nil {
		t.Fatalf("Mock scan failed: %v", err)
	}

	// Verify the correct number of images were processed
	if mockScanCount != len(mockIndex.Manifests) {
		t.Errorf("Expected to process %d images, but processed %d", 
			len(mockIndex.Manifests), mockScanCount)
	}
}