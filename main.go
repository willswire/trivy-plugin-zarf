package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// OCIIndex represents the structure of an OCI index.json file
type OCIIndex struct {
	Manifests []Manifest `json:"manifests"`
}

// Manifest represents an entry in the manifests array
type Manifest struct {
	MediaType string                 `json:"mediaType"`
	Digest    string                 `json:"digest"`
	Size      int                    `json:"size"`
	Annotations map[string]string    `json:"annotations,omitempty"`
}

func main() {
	var helpFlag bool
	flag.BoolVar(&helpFlag, "h", false, "Display help information")
	flag.Parse()
	args := flag.Args()

	if helpFlag || len(args) == 0 {
		fmt.Println("Trivy Zarf Plugin - Scan container images in Zarf packages")
		fmt.Println("\nUsage: trivy plugin run zarf <zarf-package.tar>")
		fmt.Println("\nExample: trivy plugin run zarf my-package.tar.zst")
		fmt.Println("\nThis plugin extracts and scans all container images in a Zarf package.")
		os.Exit(0)
	}

	zarfPackage := args[0]
	if !fileExists(zarfPackage) {
		fmt.Printf("Error: Zarf package %s does not exist\n", zarfPackage)
		os.Exit(1)
	}

	// Create a temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "trivy-zarf-*")
	if err != nil {
		fmt.Printf("Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	// Extract the Zarf package
	fmt.Println("Extracting Zarf package...")
	if err := extractZarfPackage(zarfPackage, tempDir); err != nil {
		fmt.Printf("Error extracting Zarf package: %v\n", err)
		os.Exit(1)
	}

	// Find and process the OCI layout
	ociDir := filepath.Join(tempDir, "images")
	if !dirExists(ociDir) {
		fmt.Printf("Error: No images directory found in Zarf package\n")
		os.Exit(1)
	}

	// Scan each image in the OCI layout
	if err := scanOCIImages(ociDir); err != nil {
		fmt.Printf("Error scanning images: %v\n", err)
		os.Exit(1)
	}
}

func extractZarfPackage(packagePath, targetDir string) error {
	// Handle different package extensions (tar, tar.zst, etc.)
	fmt.Printf("Extracting Zarf package: %s\n", packagePath)
	
	// Use the syntax that matches your Zarf version
	cmd := exec.Command("zarf", "tools", "archiver", "decompress", packagePath, targetDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	
	if err != nil {
		return fmt.Errorf("zarf decompression failed: %w", err)
	}
	
	fmt.Printf("Package extracted to: %s\n", targetDir)
	return nil
}

func scanOCIImages(ociDir string) error {
	indexPath := filepath.Join(ociDir, "index.json")
	if !fileExists(indexPath) {
		return fmt.Errorf("index.json not found in %s", ociDir)
	}

	// Read and parse the index.json file
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("reading index.json: %w", err)
	}

	var ociIndex OCIIndex
	if err := json.Unmarshal(indexData, &ociIndex); err != nil {
		return fmt.Errorf("parsing index.json: %w", err)
	}

	// No images to scan
	if len(ociIndex.Manifests) == 0 {
		fmt.Println("No images found in the Zarf package")
		return nil
	}

	// Scan each image listed in the index
	fmt.Printf("Found %d images to scan\n", len(ociIndex.Manifests))
	
	for i, manifest := range ociIndex.Manifests {
		imageName := getImageName(manifest)
		mediaType := manifest.MediaType
		fmt.Printf("\n==================================================\n")
		fmt.Printf("Scanning image %d/%d: %s\n", i+1, len(ociIndex.Manifests), imageName)
		fmt.Printf("Media type: %s\n", mediaType)
		fmt.Printf("==================================================\n")
		
		// Create a temporary index.json with just this image
		tempIndex := OCIIndex{
			Manifests: []Manifest{manifest},
		}
		
		tempIndexDir, err := os.MkdirTemp("", "trivy-image-*")
		if err != nil {
			return fmt.Errorf("creating temp directory: %w", err)
		}
		defer os.RemoveAll(tempIndexDir)
		
		// Copy the OCI layout structure
		if err := copyOCILayout(ociDir, tempIndexDir); err != nil {
			return fmt.Errorf("copying OCI layout: %w", err)
		}
		
		// Write the temporary index.json
		tempIndexData, err := json.Marshal(tempIndex)
		if err != nil {
			return fmt.Errorf("marshaling temp index: %w", err)
		}
		
		if err := os.WriteFile(filepath.Join(tempIndexDir, "index.json"), tempIndexData, 0644); err != nil {
			return fmt.Errorf("writing temp index.json: %w", err)
		}
		
		// Run Trivy on this image with additional options
		cmd := exec.Command("trivy", "image", "--input", tempIndexDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Trivy scan failed for image %s: %v\n", imageName, err)
			// Continue to the next image instead of failing completely
		}
	}

	return nil
}

func copyOCILayout(srcDir, destDir string) error {
	// Copy blobs directory
	blobsDir := filepath.Join(srcDir, "blobs")
	if dirExists(blobsDir) {
		if err := copyDir(blobsDir, filepath.Join(destDir, "blobs")); err != nil {
			return fmt.Errorf("copying blobs: %w", err)
		}
	}
	
	// Copy oci-layout file
	ociLayoutPath := filepath.Join(srcDir, "oci-layout")
	if fileExists(ociLayoutPath) {
		if err := copyFile(ociLayoutPath, filepath.Join(destDir, "oci-layout")); err != nil {
			return fmt.Errorf("copying oci-layout: %w", err)
		}
	}
	
	return nil
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		
		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	
	_, err = io.Copy(out, in)
	return err
}

func getImageName(manifest Manifest) string {
	// Try to get a readable name from annotations
	if manifest.Annotations != nil {
		if name, ok := manifest.Annotations["org.opencontainers.image.ref.name"]; ok {
			return name
		}
	}
	
	// Fallback to using the digest
	digest := manifest.Digest
	if len(digest) > 20 {
		parts := strings.Split(digest, ":")
		if len(parts) > 1 {
			return parts[1][:16] // Use first 16 chars of the hash
		}
	}
	
	return digest
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
