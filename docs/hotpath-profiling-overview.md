# Hotpath Profiling Workflow Overview

The `hotpath-profile` GitHub Actions workflow runs a lightweight benchmark so we can quickly compare how the main execution path performs on a pull request versus the base branch.

## What the workflow builds

1. **Compile the binary** – We build the ShadowMap binary with the profiling feature flags enabled.
2. **Run focused benchmarks** – The workflow runs the `examples/benchmark` target twice, once to measure timing data and once to record allocation counts.
3. **Compare pull request vs. base branch** – After the pull request metrics are collected, the workflow checks out the base branch and repeats the measurements so we can spot regressions.
4. **Publish the results** – The collected JSON metrics are uploaded as an artifact and rendered in the job summary so reviewers can read them without downloading anything.

## Why the cache might be missing

The workflow uses `Swatinem/rust-cache` to reuse compiled dependencies between runs. When the cache logs `Cache not found for keys ...`, it simply means we do not yet have a saved cache for that exact key. Common reasons include:

- The workflow is running for the first time on a branch.
- The toolchain or dependency lockfile changed, invalidating the previous cache.
- GitHub rotated runners and the cache has not been restored yet.

After the run completes, the job saves the new cache key so the next invocation should hit the cache and skip rebuilding unchanged dependencies.

Share this explanation with anyone who sees the cache miss message—it is informational and does not indicate a failure in the profiling workflow.
