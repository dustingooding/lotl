# Contributing to lotl

## Developer Setup

### Prerequisites

- **mise** (or rustup for Rust-only)
- **Android NDK r26d** (if building for Android)

### First Time Setup

```bash
# Install mise
curl https://mise.run | sh
eval "$(mise activate bash)"

# Clone repository
git clone https://github.com/dustingooding/lotl
cd lotl

# Install tools and dependencies
mise trust
mise install
just setup
```

### Verify Setup

```bash
just check
```

Pre-commit hooks are automatically installed by `just setup`. These hooks run:

- Format checking (`just fmt-check`)

The hooks run automatically before each commit. Run `just ci` manually before pushing to catch other issues.

## Development Guidelines

### Code Quality

All code must pass:

- `cargo fmt` - Formatting (see `.rustfmt.toml`)
- `cargo clippy` - Linting (zero warnings)
- `cargo test` - All tests passing
- `cargo deny` - License and security checks

Run locally before pushing:

```bash
just ci
```

### Dependency Management

Use specific versions without wildcards or caret/tilde operators.

```toml
# Good
serde = "1.0"
rand = "0.8"

# Bad
serde = "*"         # Wildcard
serde = "^1.0"      # Caret
serde = "~1.0"      # Tilde
```

When adding dependencies:

1. Check latest version on crates.io
2. Use major.minor format (e.g., "1.0", "0.8")
3. Run `just check` to verify
4. Cargo.lock pins exact versions for reproducibility

### Testing

Follow Test-Driven Development (TDD):

1. Write a failing test first
2. Implement the minimum code to pass
3. Refactor while keeping tests green

Write tests for:

- Public API functions
- Error conditions
- Edge cases

```bash
just test
just coverage
```

Aim for >80% code coverage (enforced by CI).

### Documentation

- Add `///` doc comments for public APIs
- Use `//!` module-level docs
- Include examples in doc comments
- Run `just docs` to build and view

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/) with [Gitmoji](https://gitmoji.dev/):

```text
✨ feat: add key rotation automation
🐛 fix: handle session expiration correctly
📝 docs: update README with Android setup
✅ test: add integration tests for X3DH
🔧 chore: update dependencies
♻️ refactor: simplify storage abstraction
🔒 security: update dependencies with CVE fixes
⚡ perf: optimize message encryption
```

### Pull Request Process

1. Create feature branch: `git checkout -b my-feature`
2. Make changes
3. Run `just ci` locally (must pass)
4. Push and create PR
5. CI must be green before merge
6. Squash commits on merge

## Architecture Decisions

Follow design in [LOTL_PLAN.md](/data/git/LOTL_PLAN.md):

- Transport-agnostic core
- Feature-gated integrations
- No hardcoded project names
- Platform-agnostic storage traits

## Questions?

Open an issue or discussion on GitHub.
