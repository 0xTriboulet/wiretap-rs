# Release Guide

This guide describes the release process for wiretap-rs.

## Prerequisites

- Write access to the repository
- All tests passing on the main branch
- All planned features/fixes for the release are merged

## Release Process

### 1. Update Version Numbers

Update the version in `Cargo.toml`:

```toml
[package]
version = "X.Y.Z"
```

### 2. Update CHANGELOG.md

Add a new section at the top of `CHANGELOG.md` for the new version:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features...

### Changed
- Changes to existing functionality...

### Deprecated
- Soon-to-be removed features...

### Removed
- Removed features...

### Fixed
- Bug fixes...

### Security
- Security fixes...
```

Don't forget to add the version comparison link at the bottom:

```markdown
[X.Y.Z]: https://github.com/0xTriboulet/wiretap-rs/compare/vX.Y.Z-1...vX.Y.Z
```

### 3. Commit and Push Changes

```bash
git add Cargo.toml CHANGELOG.md
git commit -m "chore: prepare release vX.Y.Z"
git push origin main
```

### 4. Create and Push Tag

```bash
# Create annotated tag
git tag -a vX.Y.Z -m "Release vX.Y.Z"

# Push the tag
git push origin vX.Y.Z
```

### 5. Automated Release

Once the tag is pushed, GitHub Actions will automatically:

1. Extract the changelog section for this version
2. Create a GitHub Release with the changelog as release notes
3. Build binaries for multiple platforms:
   - Linux x86_64
   - Linux aarch64
   - macOS x86_64
   - macOS aarch64
   - Windows x86_64
4. Upload binaries to the release

### 6. Verify Release

1. Go to the [Releases page](https://github.com/0xTriboulet/wiretap-rs/releases)
2. Verify the release was created correctly
3. Verify all binary artifacts are uploaded
4. Test download and execution of at least one binary

### 7. Publish to crates.io (Optional)

If you want to publish to crates.io:

```bash
# Login to crates.io (one-time setup)
cargo login

# Publish
cargo publish --dry-run  # Test first
cargo publish           # Actually publish
```

**Note:** Make sure the Cargo.toml metadata is complete before publishing to crates.io.

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backwards compatible manner
- **PATCH** version for backwards compatible bug fixes

Given the current pre-1.0 status:
- **0.Y.Z** versions may have breaking changes between minor versions
- Once 1.0 is released, semantic versioning will be strictly followed

## Hotfix Releases

For urgent bug fixes:

1. Create a hotfix branch from the tag: `git checkout -b hotfix/vX.Y.Z+1 vX.Y.Z`
2. Make the fix and update CHANGELOG.md
3. Update version in Cargo.toml to X.Y.Z+1
4. Commit, merge to main, and follow the regular release process

## Troubleshooting

### Release workflow fails

Check the GitHub Actions logs for specific errors. Common issues:

- **Changelog extraction fails**: Make sure the version heading in CHANGELOG.md exactly matches `## [X.Y.Z]`
- **Build fails**: Ensure the code builds locally with `cargo build --release`
- **Cross-compilation fails**: Some targets may require specific system dependencies

### Tag already exists

If you need to re-tag:

```bash
# Delete local tag
git tag -d vX.Y.Z

# Delete remote tag
git push origin :refs/tags/vX.Y.Z

# Create new tag
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

**Warning:** Only do this if the release hasn't been widely distributed yet.

## Post-Release

1. Announce the release:
   - Update README.md if necessary
   - Consider posting to relevant forums/communities
   - Update any external documentation

2. Monitor for issues:
   - Watch for bug reports related to the new release
   - Be prepared to do a hotfix release if critical bugs are found

3. Plan next release:
   - Review open issues and PRs
   - Set milestones for the next version
