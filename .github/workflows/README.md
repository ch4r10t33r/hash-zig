# GitHub Workflows

This directory contains GitHub Actions workflows for the hash-zig project.

## Workflows

### 1. CI (`ci.yml`)
Runs on every push and pull request to main branches:
- **Lint**: Checks code style and formatting
- **Test**: Runs unit tests on Ubuntu, macOS, and Windows
- **Build Examples**: Ensures all examples compile correctly

### 2. Performance Benchmark (`performance-benchmark.yml`)
Runs on pull requests and can be triggered manually:
- **Benchmarks current PR** against the base version
- **Measures key generation, signing, and verification performance**
- **Reports performance improvements** in PR comments
- **Tests multiple lifetimes** (2^10 and 2^16 signatures)

## Performance Benchmarking

### What it measures
- **Key Generation Time**: Time to generate keypairs for different lifetimes
- **Sign Time**: Time to sign a message
- **Verify Time**: Time to verify a signature
- **Memory Usage**: Implicitly through execution time

### How it works
1. **Checkout current PR** and run benchmarks
2. **Checkout base version** (previous commit) and run same benchmarks
3. **Compare results** and calculate percentage improvements
4. **Report results** in GitHub PR summary and console output

### Benchmark Results Format
The benchmark outputs results in a structured format:
```
BENCHMARK_RESULT: 2^10:keygen:1.234567
BENCHMARK_RESULT: 2^10:sign:0.000123
BENCHMARK_RESULT: 2^10:verify:0.000456
```

### Running Benchmarks Locally

#### Quick Benchmark
```bash
zig build benchmark
```

#### Detailed Benchmark with Optimizations
```bash
zig build benchmark -Doptimize=ReleaseFast
```

#### Custom Benchmark Script
```bash
zig build-exe scripts/benchmark.zig -OReleaseFast --dep hash-zig -Mhash-zig=src/root.zig
./benchmark
```

### Understanding Results

#### Key Generation
- **2^10 (1,024 signatures)**: Should complete in ~30-60 seconds
- **2^16 (65,536 signatures)**: Should complete in ~5-15 minutes
- **Improvement**: Positive percentage means faster generation

#### Sign/Verify
- **Sign**: Should complete in ~100-500ms
- **Verify**: Should complete in ~50-200ms
- **Improvement**: Positive percentage means faster operations

### Performance Targets

Based on the optimization work, we expect:
- **2-3x improvement** in key generation time
- **10-30% improvement** in sign/verify operations
- **Reduced memory allocations** (measured indirectly through speed)

### Troubleshooting

#### Benchmark Fails
1. Check that the code compiles: `zig build -Doptimize=ReleaseFast`
2. Verify tests pass: `zig build test`
3. Check for memory issues on large lifetimes

#### Inconsistent Results
1. Run multiple times to get average
2. Ensure system is not under heavy load
3. Use ReleaseFast optimization mode

#### CI Workflow Issues
1. Check that the base commit exists
2. Verify Zig version compatibility
3. Check artifact upload permissions

### Adding New Benchmarks

To add new performance tests:

1. **Add to benchmark script** (`scripts/benchmark.zig`):
   ```zig
   // New benchmark
   const new_start = std.time.nanoTimestamp();
   // ... perform operation ...
   const new_end = std.time.nanoTimestamp();
   const new_duration = @as(f64, @floatFromInt(new_end - new_start)) / 1_000_000_000.0;
   std.debug.print("BENCHMARK_RESULT: new_metric:{d:.6}\n", .{new_duration});
   ```

2. **Update workflow** to capture new metrics:
   ```yaml
   NEW_METRIC=$(grep "BENCHMARK_RESULT: new_metric:" results.txt | cut -d: -f2)
   echo "new_metric=$NEW_METRIC" >> $GITHUB_OUTPUT
   ```

3. **Add to performance analysis**:
   ```yaml
   echo "| New Metric | ${{ steps.base.outputs.new_metric }}s | ${{ steps.current.outputs.new_metric }}s | ${improvement}% |" >> $GITHUB_STEP_SUMMARY
   ```

## Workflow Triggers

### Automatic Triggers
- **Push to main/master/develop**: Runs CI
- **Pull Request to main/master/develop**: Runs CI + Performance Benchmark

### Manual Triggers
- **Workflow Dispatch**: Can manually trigger performance benchmark
- **API Triggers**: Can be triggered via GitHub API

## Dependencies

### Required Tools
- **Zig 0.14.1**: For compilation and testing
- **bc**: For percentage calculations (available in Ubuntu runners)
- **git**: For checking out different versions

### Optional Tools
- **perf**: For detailed performance analysis (if needed)
- **valgrind**: For memory profiling (if needed)

## Best Practices

1. **Always use ReleaseFast** for performance benchmarks
2. **Run multiple iterations** for stable results
3. **Document performance targets** in PR descriptions
4. **Include performance context** in commit messages
5. **Monitor trends** over time to catch regressions