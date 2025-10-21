# Release Process

This repository uses a controlled release process that creates tagged releases through pull requests to the release branch.

## How It Works

### 1. Release Branch Process
Releases are created when pull requests are merged to the `release` branch:
- Analyzes commit messages to determine the next version (semantic versioning)
- Updates the version in `build.zig.zon`
- Creates a Git tag for the release
- Creates a GitHub release with the new version

### 2. Release Branch Workflow
The `auto-release.yml` workflow:
- **Triggers**: On pull request merge to `release` branch
- **Updates**: Version in `build.zig.zon`
- **Creates**: Git tag and GitHub release
- **Generates**: Changelog from commits

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

1. **Create pull request** from `main` to `release` branch
2. **Merge pull request** to `release` branch
3. **Workflow triggers** and analyzes commits
4. **Version is determined** using semantic versioning
5. **Release is created** automatically with tag and GitHub release

## Benefits

- ✅ **Controlled releases** - Releases only when explicitly merged to release branch
- ✅ **Semantic versioning** - Automatic version detection
- ✅ **Manual override** - Can specify version bump level
- ✅ **Review process** - Pull requests allow for review before release
- ✅ **Changelog generation** - Automatic changelog from commits

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
2. Run the "Auto Release on Release Branch" workflow manually
3. Or create a pull request from main to release branch and merge it

## Workflow Files

- `auto-release.yml` - **ACTIVE** - Creates releases when PRs are merged to release branch
- `ci.yml` - **ACTIVE** - Runs tests and CI on main branch
