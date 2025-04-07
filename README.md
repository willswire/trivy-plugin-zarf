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
# Install the plugin from the Trivy Plugin Database
trivy plugin install zarf

# Or, install it using the fully qualified reference
trivy plugin install github.com/willswire/trivy-plugin-zarf

# Verify installation
trivy plugin list
```

## Usage

### Command Syntax

```bash
trivy zarf scan [flags] {zarf-package-foo-amd64-1.2.3.tar.zst | oci://registry.example.com/path/to/foo:1.2.3}
```

### Helptext

```
Scan a Zarf package

Usage:
  trivy-plugin-zarf scan [flags] packageRef

Examples:
# Scan a local zarf package:
trivy zarf scan zarf-package-foo-amd64-1.2.3.tar.zst

# Scan a package directly from an OCI registry:
trivy zarf scan oci://registry.example.com/path/to/foo:1.2.3

# Use a mirrored vulnerability database:
trivy zarf scan --db-repository=https://registry.example.com/trivy-db oci://registry.example.com/path/to/foo:1.2.3

# Skip signature validation for OCI registry packages:
trivy zarf scan --skip-signature-validation oci://registry.example.com/path/to/foo:1.2.3

# Pull and scan a specific architecture from an OCI registry:
trivy zarf scan --arch=arm64 oci://registry.example.com/path/to/foo:1.2.3

# Save JSON scan results to a directory:
trivy zarf scan --output=./results zarf-package-foo-amd64-1.2.3.tar.zst

Flags:
      --arch string                 Env: TRIVY_PLUGIN_ZARF_SCAN_ARCH
                                    CfgFile: scan.arch
                                    Architecture to pull for OCI images. If not specified, the architecture of the host will be used.
      --db-repository string        Env: TRIVY_PLUGIN_ZARF_SCAN_DB_REPOSITORY
                                    CfgFile: scan.db-repository
                                    Trivy DB repository to use (default ghcr.io/aquasecurity/trivy-db) (default "ghcr.io/aquasecurity/trivy-db")
  -h, --help                        help for scan
  -o, --output string               Env: TRIVY_PLUGIN_ZARF_SCAN_OUTPUT
                                    CfgFile: scan.output
                                    Output directory for JSON scan results. If not specified, the results will be printed to stdout.
      --skip-signature-validation   Env: TRIVY_PLUGIN_ZARF_SCAN_SKIP_SIGNATURE_VALIDATION
                                    CfgFile: scan.skip-signature-validation
                                    Skip signature validation when pulling a zarf package from an OCI registry.

Global Flags:
  -c, --config string       Env: TRIVY_PLUGIN_ZARF_CONFIG
                            Optional config file (default $HOME/.trivy_plugin_zarf.yaml)
      --log-format string   Env: TRIVY_PLUGIN_ZARF_LOG_FORMAT
                            CfgFile: log-format
                            Log format [console, json, dev, none] (default "console")
  -l, --log-level string    Env: TRIVY_PLUGIN_ZARF_LOG_LEVEL
                            CfgFile: log-level
                            Log level [debug, info, warn, error] (default "info")
      --no-color            Env: TRIVY_PLUGIN_ZARF_NO_COLOR
                            CfgFile: no-color
                            Disable colorized output
```

## Complete Workflow Example

```bash
# Install the plugin
trivy plugin install zarf

# Pull a Zarf package from an OCI registry
zarf package pull --skip-signature-validation oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0

# Scan the downloaded package and save results to a directory
trivy zarf scan --output ./scan-results zarf-package-dos-games-arm64-1.2.0.tar.zst

# Or scan directly from OCI in one step
trivy zarf scan --skip-signature-validation --output ./scan-results oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0

# Pull and scan a specific architecture from OCI in one step
trivy zarf scan --arch arm64 --output ./scan-results oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/willswire/trivy-plugin-zarf.git
cd trivy-plugin-zarf

# Build the plugin
go build

# Or just run it
go run main.go --help
```

### Local Testing

Run the plugin binary directly:

```bash
# Test with a local package
go run main.go scan zarf-package-dos-games-arm64-1.2.0.tar.zst

# Test with an OCI reference
go run main.go scan oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0

# Test with output flags
go run main.go scan --output ./results zarf-package-dos-games-arm64-1.2.0.tar.zst

# Test with architecture specification
go run main.go scan --arch arm64 oci://ghcr.io/zarf-dev/packages/dos-games:1.2.0
```

### Linking for Development

You can also link the development version to test as a Trivy plugin:

```bash
# Build the binary
go build

# Link the development version (from the plugin directory)
ln -sf "$(pwd)/trivy-plugin-zarf" "$HOME/.trivy/plugins/zarf"

# Test as a Trivy plugin
trivy zarf scan zarf-package-dos-games-arm64-1.2.0.tar.zst
```

## Testing

The project includes various tests to verify functionality:

```bash
# Run just unit tests
go test -v ./...

# Run all tests
go test -tags=integration -v ./...

# Run tests with coverage report
go test -tags=integration -coverprofile=coverage.out -v ./...
go tool cover -html=coverage.out
```

### Integration Testing

For integration tests, you'll need:

1. Zarf and Trivy installed and in your PATH
2. The ability to pull an OCI artifact from public `ghcr.io`

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
