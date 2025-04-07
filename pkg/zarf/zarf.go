package zarf

import (
	"fmt"
	"github.com/willswire/trivy-plugin-zarf/pkg/logger"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExtractZarfPackage extracts a Zarf package from the specified packagePath to the targetDir.
// Supports handling various package extensions such as tar and tar.zst.
// Returns an error if the decompression process fails.
func ExtractZarfPackage(packagePath, targetDir string) error {
	// Handle different package extensions (tar, tar.zst, etc.)
	logger.Default().Info("Extracting Zarf package", "packagePath", packagePath, "targetDir", targetDir)

	// Use the syntax that matches your Zarf version
	cmd := exec.Command("zarf", "tools", "archiver", "decompress", packagePath, targetDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	if err != nil {
		return fmt.Errorf("zarf decompression failed: %w", err)
	}

	logger.Default().Info("Package extracted", "targetDir", targetDir)
	return nil
}

// PullZarfPackage pulls a Zarf package from an OCI registry and stores it in the specified directory.
func PullZarfPackage(ociRef, targetDir string, skipSignatureValidation bool, architecture string) (string, error) {
	// Ensure the reference starts with oci://
	if !strings.HasPrefix(ociRef, "oci://") {
		return "", fmt.Errorf("invalid OCI reference format: %s (must start with oci://)", ociRef)
	}

	logger.Default().Info("Pulling Zarf package from OCI registry", "ociRef", ociRef)

	// Create command to pull the package using zarf CLI but with improved handling
	cmd := exec.Command("zarf", "package", "pull", ociRef, "-o", targetDir)
	if skipSignatureValidation {
		cmd.Args = append(cmd.Args, "--skip-signature-validation")
	}

	// Add architecture flag if specified
	if architecture != "" {
		cmd.Args = append(cmd.Args, "-a", architecture)
	}

	// Use zarf package pull command to pull the package to the targetDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	if err != nil {
		return "", fmt.Errorf("zarf package pull failed: %w", err)
	}

	logger.Default().Info("Package pulled", "targetDir", targetDir)

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
