# Trivy Plugin Zarf

A Trivy plugin for scanning container images in Zarf packages from local files or OCI registries.

## Overview

This plugin allows you to scan all container images within a Zarf package for vulnerabilities using Trivy, without requiring any manual extraction or transformation steps. It automatically:

1. Extracts the Zarf package (from local file or OCI registry)
2. Parses the OCI image structure
3. Scans each image in the package sequentially
4. Reports vulnerabilities for each image

The plugin handles both `application/vnd.oci.image.manifest.v1+json` and `application/vnd.docker.distribution.manifest.v2+json` format images, and supports both local Zarf packages and OCI-stored packages via `oci://` references.

## Prerequisites

- [Trivy](https://github.com/aquasecurity/trivy) >= 0.41.0 (for vulnerability scanning)
- [Zarf](https://github.com/defenseunicorns/zarf) >= 0.25.0 (for package decompression)

## Installation

```bash
# Install the plugin
trivy plugin install github.com/willswire/trivy-plugin-zarf

# Verify installation
trivy plugin list
```

## Usage

### Command Syntax

```bash
trivy zarf [flags] <zarf-package.tar> or <oci://registry/repository:tag>
```

### Flags/Options

| Flag | Shorthand | Description |
|------|-----------|-------------|
| `--help` | `-h` | Display help information |
| `--output DIR` | `-o DIR` | Save scan results as JSON files in specified directory |
| `--skip-signature-validation` | | Skip signature validation when pulling from OCI registry |
| `--arch ARCHITECTURE` | `-a ARCHITECTURE` | Architecture to pull for OCI images (e.g., `amd64`, `arm64`) |

### Basic Examples

Scan a local Zarf package:

```bash
trivy zarf zarf-package-dos-games-arm64-1.2.0.tar.zst
```

Scan a package directly from an OCI registry:

```bash
trivy zarf oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

Skip signature validation when pulling from OCI registry:

```bash
trivy zarf --skip-signature-validation oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

Pull and scan a specific architecture from an OCI registry:

```bash
trivy zarf --arch amd64 oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

### Output Options

Save JSON scan results to a directory:

```bash
trivy zarf --output ./scan-results zarf-package-dos-games-arm64-1.2.0.tar.zst
```

This will create individual JSON files for each image in the specified directory, making it easier to process results programmatically or integrate with other tools.

## Complete Workflow Example

```bash
# Install the plugin
trivy plugin install github.com/willswire/trivy-plugin-zarf

# Pull a Zarf package from OCI registry
zarf package pull --skip-signature-validation oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0

# Scan the downloaded package and save results to a directory
trivy zarf --output ./scan-results zarf-package-dos-games-arm64-1.2.0.tar.zst

# Or scan directly from OCI in one step
trivy zarf --skip-signature-validation --output ./scan-results oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0

# Pull and scan a specific architecture from OCI in one step
trivy zarf --arch arm64 --output ./scan-results oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/willswire/trivy-plugin-zarf.git
cd trivy-plugin-zarf

# Build the plugin
go build
```

### Local Testing

Run the plugin binary directly:

```bash
# Test with a local package
./trivy-plugin-zarf zarf-package-dos-games-arm64-1.2.0.tar.zst

# Test with an OCI reference
./trivy-plugin-zarf oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0

# Test with output flags
./trivy-plugin-zarf --output ./results zarf-package-dos-games-arm64-1.2.0.tar.zst

# Test with architecture specification
./trivy-plugin-zarf --arch arm64 oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

### Linking for Development

You can also link the development version to test as a Trivy plugin:

```bash
# Link the development version (from the plugin directory)
ln -sf "$(pwd)/trivy-plugin-zarf" "$HOME/.trivy/plugins/zarf"

# Test as a Trivy plugin
trivy zarf zarf-package-dos-games-arm64-1.2.0.tar.zst
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

### Integration Testing

For integration tests, you'll need:

1. Zarf and Trivy installed and in your PATH
2. A Zarf package to test with (e.g., `zarf-package-dos-games-arm64-1.2.0.tar.zst`)

You can download a test package with:

```bash
zarf package pull --skip-signature-validation oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

## Release Process

This project uses [GoReleaser](https://goreleaser.com/) to publish releases. The release process is automated through GitHub Actions.

To create a new release:

1. Tag the commit with a version: `git tag -a v0.X.Y -m "Release v0.X.Y"`
2. Push the tag: `git push origin v0.X.Y`
3. GitHub Actions will automatically build and publish the release artifacts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Submit a pull request

## License

Apache License, Version 2.0
