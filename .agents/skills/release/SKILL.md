---
name: release
description: Publishes ziglint releases. Use when releasing, versioning, tagging, or publishing a new version.
---

# Releasing ziglint

## Quick Release Checklist

1. Write release notes in `docs/releases/vX.Y.Z.md`
2. Commit changes
3. Tag and push: `git tag vX.Y.Z && git push && git push --tags`

## Release Notes

Create a markdown file at `docs/releases/vX.Y.Z.md` (must match the tag name exactly).

Example for `docs/releases/v0.1.0.md`:

```markdown
## What's New

- Initial release of ziglint
- Zig linting and style checks

## Breaking Changes

None (initial release)

## Installation

```bash
mise use github:rockorager/ziglint
```
```

If no release notes file exists, the release will use "Release vX.Y.Z" as the body.

## What Happens on Release

When you push a tag matching `v*`:

1. **Build job** - Cross-compiles on ubuntu-latest for:
   - `aarch64-macos`
   - `x86_64-linux`
   - `x86_64-windows`
2. **Release job** - Creates GitHub release with:
   - Tarballs (`.tar.gz`) for Unix platforms
   - Zip (`.zip`) for Windows
   - `checksums.txt` with SHA256 hashes
   - Release notes from `docs/releases/vX.Y.Z.md`

## Prerelease Tags

Tags containing `-` (e.g., `v0.1.0-beta`, `v0.2.0-rc1`) are automatically marked as prereleases on GitHub.

## Installing via mise

Users can install ziglint directly from GitHub releases:

```bash
mise use github:rockorager/ziglint
```
