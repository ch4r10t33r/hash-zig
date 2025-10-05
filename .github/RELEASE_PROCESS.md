# Release Process

This repository uses an automated release process that works with protected branches by creating pull requests instead of pushing directly to the main branch.

## How It Works

### 1. Automatic Release Detection
When commits are pushed to the `master` or `main` branch, the release workflow automatically:
- Analyzes commit messages to determine the next version (semantic versioning)
- Creates a new release branch (`release/vX.Y.Z`)
- Updates the version in `build.zig.zon`
- Creates a pull request to merge the release into the main branch

### 2. Release Branch Workflow
The `release-branch.yml` workflow:
- **Triggers**: On push to `master`/`main` branches
- **Creates**: A new release branch with version bump
- **Opens**: A pull request for the release
- **Waits**: For the PR to be merged

### 3. Release Creation
The `release-on-pr-merge.yml` workflow:
- **Triggers**: When a release PR is merged
- **Creates**: Git tag and GitHub release
- **Cleans up**: The release branch

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
2. **Workflow triggers** and creates release branch
3. **Review the PR** that was created
4. **Merge the PR** to trigger the release
5. **Release is created** automatically with tag and GitHub release

## Benefits

- ✅ **Works with protected branches** - No direct pushes required
- ✅ **Reviewable releases** - All releases go through PR review
- ✅ **Automatic cleanup** - Release branches are deleted after merge
- ✅ **Semantic versioning** - Automatic version detection
- ✅ **Manual override** - Can specify version bump level

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

- `release-branch.yml` - Creates release branches and PRs
- `release-on-pr-merge.yml` - Creates releases when PRs are merged
- `release-on-merge.yml` - **DEPRECATED** - Old workflow that pushed directly
