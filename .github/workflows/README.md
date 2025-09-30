# GitHub Actions Workflows

## CI Workflow

The `ci.yml` workflow runs on every push or pull request to `main`, `master`, or `develop` branches.

### Jobs

#### 1. Lint
- **Runs on:** Ubuntu Latest
- **Zig Version:** 0.14.1
- **Steps:**
  - Checkout code
  - Setup Zig
  - Run `zig build lint` (using zlinter)

#### 2. Test
- **Runs on:** Ubuntu, macOS, Windows
- **Zig Version:** 0.14.1
- **Matrix Strategy:** Tests on 3 platforms
- **Steps:**
  - Checkout code
  - Setup Zig
  - Run `zig build test`
  - Build library with `zig build`

#### 3. Build Examples
- **Runs on:** Ubuntu Latest
- **Zig Version:** 0.14.1
- **Dependencies:** Runs after lint and test jobs succeed
- **Steps:**
  - Build library
  - Run example application

### Trigger Events

The workflow triggers on:
- **Push** to main, master, or develop branches
- **Pull requests** targeting main, master, or develop branches

### Badge

The CI status badge in README.md:

```markdown
[![CI](https://github.com/ch4r10t33r/hash-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4r10t33r/hash-zig/actions/workflows/ci.yml)
```

### Local Testing

Before pushing, you can run the same checks locally with Zig 0.14.1:

```bash
# Run linting
zig build lint

# Run tests
zig build test

# Build library
zig build

# Run example
zig build example
```

### Supported Zig Version

- **0.14.1** - Required version (zlinter only supports 0.14.x)

**Note:** The project uses zlinter which currently only supports Zig 0.14.x. Once zlinter adds support for Zig 0.15+, the CI will be updated.

### Platform Support

- **Linux** (Ubuntu Latest)
- **macOS** (macOS Latest)
- **Windows** (Windows Latest)

All tests must pass on all platforms before merging to protected branches.

### Linter (zlinter)

The project uses [zlinter](https://github.com/kurtwagner/zlinter) - an extendable Zig linter integrated into the build system.

**Enabled rules:**
- `field_naming` - Enforce field naming conventions
- `declaration_naming` - Enforce declaration naming conventions (snake_case)
- `function_naming` - Enforce function naming conventions
- `no_unused` - Detect unused declarations
- `no_deprecated` - Warn about deprecated API usage

**Customization:**
See `build.zig` to add/remove rules or adjust severity levels.
