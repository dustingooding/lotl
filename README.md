# lotl

[![CI](https://github.com/dustingooding/lotl/workflows/CI/badge.svg)](https://github.com/dustingooding/lotl/actions)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Signal Protocol (X3DH + Double Ratchet) session management with plug-in transports.

## Features

- **Signal Protocol encryption** - X3DH key agreement + Double Ratchet
- **Automated key management** - Rotation, maintenance, prekey bundles
- **Storage abstraction** - SQLite/SQLCipher with platform keychain integration
- **Cross-platform** - Linux, Android, iOS (via UniFFI)
- **Plug-in transports** - Nostr support (feature-gated), extensible architecture
- **Post-quantum ready** - Kyber-1024 support via libsignal

## Quick Start

### Prerequisites

- Rust 1.89.0 (managed via `mise` or `rustup`)
- For Android: NDK r26d

### Developer Setup

```bash
# Install mise (tool version manager)
curl https://mise.run | sh
eval "$(mise activate bash)"

# Clone and setup
git clone https://github.com/dustingooding/lotl
cd lotl
mise install             # Install all tools (Rust, just, etc.)
just setup               # Install dev dependencies
```

### Building

```bash
# Linux (debug)
just build

# Linux (release)
just build-release

# Android (debug)
just build-android

# Android (release)
just build-android-release
```

## Development Workflow

```bash
just check               # Run all quality checks (fmt, clippy, test)
just test                # Run tests only
just coverage            # Generate coverage report
just docs                # Build and open documentation
just audit               # Security audit
just ci                  # Run full CI-like checks locally
```

## License

This project is licensed under the [AGPL-3.0-only](LICENSE) license.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
