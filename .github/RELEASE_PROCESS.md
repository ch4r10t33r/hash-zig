# Release Process

This repository uses an automated release process that creates tagged releases directly when commits are pushed to the master branch.

## How It Works

### 1. Automatic Release Detection
When commits are pushed to the `master` or `main` branch, the release workflow automatically:
- Analyzes commit messages to determine the next version (semantic versioning)
- Updates the version in `build.zig.zon`
- Creates a Git tag for the release
- Creates a GitHub release with the new version

### 2. Direct Release Workflow
The `release-on-master.yml` workflow:
- **Triggers**: On push to `master`/`main` branches
- **Updates**: Version in `build.zig.zon`
- **Creates**: Git tag and GitHub release
- **Pushes**: Version bump commit back to master

## Semantic Versioning

The release process uses conventional commits to determine the version bump:

- **Major** (`1.0.0` → `2.0.0`): `feat!` or `BREAKING CHANGE`
- **Minor** (`1.0.0` → `1.1.0`): `feat`
- **Patch** (`1.0.0` → `1.0.1`): `fix`, `perf`, `refactor`, `chore`, `build`, `ci`, `docs`, `style`, `test`

### Manual Override
You can override the automatic version detection by adding a footer to your commit:
```
feat: add new feature

release: minor
```

## Release Process Steps

1. **Push commits** to `master`/`main` branch
2. **Workflow triggers** and analyzes commits
3. **Version is determined** using semantic versioning
4. **Release is created** automatically with tag and GitHub release
5. **Version bump** is committed back to master

## Benefits

- ✅ **Simple and direct** - No complex branch management
- ✅ **Automatic releases** - Creates releases on every master push
- ✅ **Semantic versioning** - Automatic version detection
- ✅ **Manual override** - Can specify version bump level
- ✅ **Immediate releases** - No waiting for PR reviews

## Troubleshooting

### Tag Already Exists
If you see "Tag already exists" errors:
1. Delete the existing tag: `git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`
2. Or use a new version number

### Protected Branch Issues
If you see "Protected branch update failed":
1. The new workflow should handle this automatically
2. Make sure the release PR is merged, not the commits pushed directly

### Manual Release
To create a manual release:
1. Go to Actions tab
2. Run the "Release Branch Workflow" manually
3. Or create a release branch manually and follow the process

## Workflow Files

- `release-on-master.yml` - **ACTIVE** - Creates releases directly on master branch updates
- `release-branch.yml` - **DEPRECATED** - Old branch-based workflow
- `release-on-pr-merge.yml` - **DEPRECATED** - Old PR-based workflow
- `release-on-merge.yml` - **DEPRECATED** - Old direct push workflow
