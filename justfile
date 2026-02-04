# justfile - Task runner for lotl development

set shell := ["bash", "-euo", "pipefail", "-c"]
cargo := "mise exec -- cargo"

# Default recipe (run when just `just` is called)
default: check

# Install development dependencies
setup:
    @echo "Installing development tools..."
    {{cargo}} install cargo-ndk@4.1.2
    {{cargo}} install cargo-tarpaulin@0.35.1
    {{cargo}} install cargo-audit@0.22.0
    {{cargo}} install cargo-deny@0.19.0
    pre-commit install
    @echo "Setup complete!"

# Run all quality checks
check: fmt-check clippy test

# Format code
fmt:
    {{cargo}} fmt --all

# Check formatting without modifying files
fmt-check:
    {{cargo}} fmt --all -- --check

# Lint with clippy (all features)
clippy:
    {{cargo}} clippy --all-features --all-targets -- -D warnings
    {{cargo}} clippy --no-default-features --all-targets -- -D warnings

# Run tests (debug)
test:
    {{cargo}} test --all-features --verbose
    {{cargo}} test --no-default-features --verbose

# Run tests (release)
test-release:
    {{cargo}} test --all-features --verbose --release
    {{cargo}} test --no-default-features --verbose --release

# Generate coverage report (local - opens HTML)
coverage:
    {{cargo}} tarpaulin --all-features --out Html --output-dir target/coverage --engine llvm
    @echo "Coverage report generated in target/coverage/tarpaulin-report.html"

# Generate coverage report (CI - XML for codecov)
coverage-ci:
    {{cargo}} tarpaulin --all-features --workspace --timeout 300 --out xml --engine llvm

# Build debug binary
build:
    {{cargo}} build

# Build release binary
build-release:
    {{cargo}} build --release

# Build for all Android targets (debug)
build-android:
    {{cargo}} ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs build

# Build for all Android targets (release)
build-android-release:
    {{cargo}} ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs build --release

# Build for single Android target (debug)
build-android-target target:
    {{cargo}} ndk --target {{target}} -o ./jniLibs build

# Build for single Android target (release)
build-android-target-release target:
    {{cargo}} ndk --target {{target}} -o ./jniLibs build --release

# Security audit
audit:
    {{cargo}} audit
    {{cargo}} deny check

# Build documentation (local - opens in browser)
docs:
    {{cargo}} doc --all-features --no-deps --document-private-items --open

# Build documentation (CI - no browser)
docs-ci:
    {{cargo}} doc --all-features --no-deps --document-private-items

# Clean build artifacts
clean:
    {{cargo}} clean
    rm -rf bindings/

# Run a full CI-like check locally
ci: fmt-check clippy test audit
    @echo "All CI checks passed!"

# List available recipes
list:
    @just --list
