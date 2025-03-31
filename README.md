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

## Try it out!

```bash
# Install the plugin
trivy plugin install github.com/willswire/trivy-plugin-zarf

# Verify installation
trivy plugin list

# Pull a package and scan it
zarf package pull --skip-signature-validation oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
trivy zarf zarf-package-dos-games-arm64-1.2.0.tar.zst
```

## Development

```bash
# Install the plugin locally for development
go build

# Run the binary directly for testing
zarf package pull --skip-signature-validation oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
./trivy-plugin-zarf zarf-package-dos-games-arm64-1.2.0.tar.zst
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
