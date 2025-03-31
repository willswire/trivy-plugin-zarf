# Trivy Plugin Zarf

A Trivy plugin for scanning container images in Zarf packages.

## Overview

This plugin allows you to scan all container images within a Zarf package for vulnerabilities using Trivy, without requiring any manual extraction or transformation steps. It automatically:

1. Extracts the Zarf package
2. Parses the OCI image structure
3. Scans each image in the package sequentially
4. Reports vulnerabilities for each image

The plugin handles both `application/vnd.oci.image.manifest.v1+json` and `application/vnd.docker.distribution.manifest.v2+json` format images.

## Prerequisites

- [Trivy](https://github.com/aquasecurity/trivy) (for vulnerability scanning)
- [Zarf](https://github.com/defenseunicorns/zarf) (for package decompression)

## Installation

```bash
# Install the plugin
trivy plugin install github.com/willswire/trivy-plugin-zarf

# Verify installation
trivy plugin list
```

## Usage

```bash
# Install the plugin locally for development
go build -o zarf
trivy plugin install .

# Scan a Zarf package
trivy plugin run zarf path/to/your-zarf-package.tar

# Or run the binary directly for testing
./zarf path/to/your-zarf-package.tar
```

The plugin will:
- Extract the Zarf package
- Find all container images
- Scan each image for vulnerabilities (regardless of manifest type)
- Report results for each image

## Building from source

```bash
# Clone the repository
git clone https://github.com/willswire/trivy-plugin-zarf.git
cd trivy-plugin-zarf

# Build
go build

# Install the plugin locally
trivy plugin install .
```

## Testing

The project includes various tests to verify functionality:

```bash
# Run all tests
go test ./...

# Run specific test groups
go test -v -run="TestFileAndDirExists|TestGetImageName"  # Unit tests
go test -v -run="TestScanOCIImagesMock"                  # Mock tests
go test -v -run="TestExtractAndScanIntegration"          # Integration tests

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Integration testing

For integration tests, you'll need:
1. Zarf and Trivy installed and in your PATH
2. A Zarf package to test with (e.g., `zarf-package-dos-games-arm64-1.2.0.tar.zst`)

You can download a test package with:
```bash
zarf package pull --skip-signature-validation oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

## License

Apache License, Version 2.0
