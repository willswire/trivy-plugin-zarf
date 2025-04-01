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
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int               `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func main() {
	var helpFlag bool
	var outputDir string
	var skipSignatureValidation bool

	flag.BoolVar(&helpFlag, "help", false, "Display help information")
	flag.BoolVar(&helpFlag, "h", false, "Display help information (shorthand)")
	flag.StringVar(&outputDir, "output", "", "Output directory for JSON scan results")
	flag.StringVar(&outputDir, "o", "", "Output directory for JSON scan results (shorthand)")
	flag.BoolVar(&skipSignatureValidation, "skip-signature-validation", false, "Skip signature validation for OCI images")
	flag.Parse()
	args := flag.Args()

	if helpFlag || len(args) == 0 {
		fmt.Println("Trivy Zarf Plugin - Scan container images in Zarf packages")
		fmt.Println("\nUsage: trivy plugin run zarf [flags] <zarf-package.tar> or <oci://registry/repository:tag>")
		fmt.Println("\nOptions:")
		fmt.Println("  -h, --help                   Display help information")
		fmt.Println("  -o, --output DIR             Save scan results as JSON files in specified directory")
		fmt.Println("  --skip-signature-validation  Skip signature validation for OCI images")
		fmt.Println("\nExamples:")
		fmt.Println("  trivy zarf my-package.tar.zst")
		fmt.Println("  trivy zarf --skip-signature-validation oci://ghcr.io/my-org/my-zarf-package:latest")
		fmt.Println("  trivy zarf --output ./results my-package.tar.zst")
		fmt.Println("\nThis plugin extracts and scans all container images in a Zarf package.")
		os.Exit(0)
	}

	// Create output directory if specified
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Printf("Error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}

	packageRef := args[0]
	// Check if it's an OCI reference or a local file
	isOCIRef := strings.HasPrefix(packageRef, "oci://")

	// Create a temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "trivy-zarf-*")
	if err != nil {
		fmt.Printf("Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			fmt.Printf("Error removing temp directory: %v\n", err)
		}
	}(tempDir)

	// Handle package according to its type
	if isOCIRef {
		// Handle OCI reference
		fmt.Println("Pulling Zarf package from OCI registry...")
		packageFile, err := pullZarfPackage(packageRef, tempDir, skipSignatureValidation)
		if err != nil {
			fmt.Printf("Error pulling Zarf package: %v\n", err)
			os.Exit(1)
		}
		// Update packageRef so it's a .tar.zst file now
		packageRef = packageFile
	}

	// Handle local file
	if !fileExists(packageRef) {
		fmt.Printf("Error: Zarf package %s does not exist\n", packageRef)
		os.Exit(1)
	}

	// Extract the Zarf package
	fmt.Println("Extracting Zarf package...")
	if err := extractZarfPackage(packageRef, tempDir); err != nil {
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
	if err := scanOCIImages(ociDir, outputDir); err != nil {
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

func pullZarfPackage(ociRef, targetDir string, skipSignatureValidation bool) (string, error) {
	// Ensure the reference starts with oci://
	if !strings.HasPrefix(ociRef, "oci://") {
		return "", fmt.Errorf("invalid OCI reference format: %s (must start with oci://)", ociRef)
	}

	fmt.Printf("Pulling Zarf package from OCI registry: %s\n", ociRef)

	cmd := exec.Command("zarf", "package", "pull", ociRef, "-o", targetDir)
	if skipSignatureValidation {
		cmd.Args = append(cmd.Args, "--skip-signature-validation")
	}

	// Use zarf package pull command to pull the package to the targetDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	if err != nil {
		return "", fmt.Errorf("zarf package pull failed: %w", err)
	}

	fmt.Printf("Package pulled to targetDir: %s\n", targetDir)

	// Find the .tar.zst file in the targetDir
	var packageFile string
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return "", fmt.Errorf("error reading target directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tar.zst") {
			packageFile = filepath.Join(targetDir, entry.Name())
			break
		}
	}

	if packageFile == "" {
		return "", fmt.Errorf("no .tar.zst file found in target directory after pull")
	}

	return packageFile, nil
}

func scanOCIImages(ociDir, outputDir string) error {
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
		defer func(path string) {
			err := os.RemoveAll(path)
			if err != nil {
				fmt.Printf("Error removing temp directory: %v\n", err)
			}
		}(tempIndexDir)

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

		// Run Trivy on this image
		var cmd *exec.Cmd
		if outputDir != "" {
			// Create a sanitized filename for JSON output
			safeImageName := sanitizeFilename(imageName)
			jsonOutputPath := filepath.Join(outputDir, safeImageName+".json")

			// Use JSON output format and save to file
			cmd = exec.Command("trivy", "image", "--format", "json", "--output", jsonOutputPath, "--input", tempIndexDir)

			fmt.Printf("Saving JSON results to: %s\n", jsonOutputPath)
		} else {
			// Standard console output
			cmd = exec.Command("trivy", "image", "--input", tempIndexDir)
		}

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
	defer func(in *os.File) {
		err := in.Close()
		if err != nil {
			fmt.Printf("Error closing file: %v\n", err)
		}
	}(in)

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func(out *os.File) {
		err := out.Close()
		if err != nil {
			fmt.Printf("Error closing file: %v\n", err)
		}
	}(out)

	_, err = io.Copy(out, in)
	return err
}

func getImageName(manifest Manifest) string {
	// Try to get a readable name from annotations
	if manifest.Annotations != nil {
		// First try org.opencontainers.image.ref.name
		if name, ok := manifest.Annotations["org.opencontainers.image.ref.name"]; ok {
			return name
		}

		// Then try org.opencontainers.image.base.name
		if name, ok := manifest.Annotations["org.opencontainers.image.base.name"]; ok {
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

// sanitizeFilename converts an image name to a safe filename
func sanitizeFilename(imageName string) string {
	// Replace common characters that are problematic in filenames
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		" ", "_",
		".", "_",
		",", "_",
		"@", "_",
		"&", "_",
		"=", "_",
		"?", "_",
		"#", "_",
		"%", "_",
		"*", "_",
		"\"", "_",
		"'", "_",
		"`", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"\\", "_",
		"!", "_",
	)

	// Perform the replacements
	sanitized := replacer.Replace(imageName)

	// Ensure we don't have multiple consecutive underscores
	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}

	// Trim underscores from start and end
	sanitized = strings.Trim(sanitized, "_")

	// If we somehow end up with an empty string, use a default name
	if sanitized == "" {
		sanitized = "unknown_image"
	}

	return sanitized
}
