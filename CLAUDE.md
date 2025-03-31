# Trivy Plugin Zarf - Development Guidelines

## Development Philosophy: The Cycles of Creation
Software, like nature, follows eternal cycles of creation and decay. Our approach embraces these truths:
- **Embrace Simplicity**: All efforts eventually return to dust; create systems that are simple and focused on serving immediate needs rather than speculative futures.
- **Value Clarity Over Novelty**: There is "nothing new under the sun" in software patterns; prefer established patterns that are well-understood.
- **Build for Impermanence**: Code is transient; optimize for maintainability and readability rather than cleverness or premature optimization.
- **Seek Essential Truth**: Strip away complexity to reveal the core purpose of each component. The eye is never satisfied with seeing more features.
- **Remember History**: Learn from past solutions; most problems have been solved before in different contexts.

## Build & Test Commands
- Build: `go build -o zarf`
- Install locally: `trivy plugin install .`
- Run: `trivy plugin run zarf <zarf-package.tar>`
- Development testing: `./zarf <zarf-package.tar>`
- CI release: Uses GoReleaser to build and package for multiple platforms

## Code Style Guidelines
- Go version: 1.21+
- Error handling: Use idiomatic Go error handling with detailed error messages
- Imports: Group standard library imports first, followed by third-party imports
- Naming: Use descriptive camelCase for variables, functions, and PascalCase for exported types
- Types: Define clear types for structured data (e.g., OCIIndex, Manifest)
- Functions: Keep functions focused on single responsibility with clear error returns
- Comments: Document exported types and complex functionality
- Error wrapping: Use fmt.Errorf with %w for error context
- Formatting: Use gofmt/goimports for consistent code formatting
- Line length: Prefer lines under 100 characters
- Logging: Use fmt.Printf for user feedback and progress reporting