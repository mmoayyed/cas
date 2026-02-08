# Gradle Build Optimizations

This document describes the Gradle build optimizations implemented to improve build and test execution performance.

## Optimizations Implemented

### 1. Dynamic Test Parallelization

**Location:** `gradle/tests.gradle`

**Change:** Modified `maxParallelForks` from a hardcoded value of `8` to dynamically use half of available processors.

**Rationale:** Different build environments have different CPU resources. Using `Runtime.runtime.availableProcessors() / 2` allows the build to scale appropriately on machines with more or fewer cores while avoiding resource contention.

**Override:** Can be overridden with `-PmaxTestForks=<value>`

**Impact:** 
- Machines with more cores will run more tests in parallel, speeding up test execution
- Machines with fewer cores won't be overloaded with too many parallel test workers
- Using half (not all) processors prevents system resource starvation

### 2. Optimized Test Memory Settings

**Location:** `gradle/tests.gradle`

**Change:** Reduced test worker max heap from `6g` to `3g`

**Rationale:** Each test worker was allocated up to 6GB of heap memory, which is excessive for most tests. By reducing to 3GB:
- More test workers can run in parallel on the same machine
- Memory usage is more efficient
- Build performance improves as more tests can run concurrently

**Override:** Can be overridden with:
- `-PtestMinHeap=<value>` (default: 512m)
- `-PtestMaxHeap=<value>` (default: 3g)

**Impact:** Reduces memory footprint per test worker, allowing more parallel execution.

### 3. Optimized Test Forking Frequency

**Location:** `gradle/tests.gradle`

**Change:** Reduced `forkEvery` from `2000` to `100`

**Rationale:** Forking a new JVM process after every 2000 test classes was too infrequent and could lead to:
- Memory leaks accumulating in long-running test JVMs
- Slower test execution as JVMs become bloated
- Unpredictable test behavior

Forking every 100 test classes provides a better balance between:
- Process startup overhead (reduced by not forking too frequently)
- Memory freshness (ensured by forking often enough)

**Override:** Can be overridden with `-PtestForkEvery=<value>`

**Impact:** More predictable test execution with better memory management.

### 4. File System Watching Optimization

**Location:** `gradle.properties`

**Change:** Explicitly disabled file watching with `org.gradle.vfs.watch=false`

**Rationale:** File system watching can cause overhead in CI environments where incremental builds are less common. Disabling it:
- Reduces background CPU usage
- Eliminates potential file watching bugs
- Improves build performance in CI

**Override:** Can be enabled for local development with `--watch-fs` flag

**Impact:** Improved build performance, especially in CI/CD pipelines.

### 5. Gradle Daemon Settings

**Location:** `gradle.properties`

**Change:** Explicitly enabled daemon and set idle timeout to 1 hour

**Rationale:** 
- Ensures the Gradle daemon is always used for better performance
- Sets a reasonable idle timeout to keep the daemon alive between builds
- Reduces build startup time by reusing warm JVMs

**Impact:** Faster build startup times, especially for repeated builds.

## Existing Optimizations (Already Enabled)

The following optimizations were already enabled in the build:

1. **Parallel builds** (`org.gradle.parallel=true`)
2. **Build cache** (`org.gradle.caching=true`)
3. **Configuration cache** (`org.gradle.unsafe.configuration-cache=true`)
4. **Configure-on-demand** (`org.gradle.configureondemand=true`)
5. **Incremental compilation** (`it.options.incremental = true`)
6. **Parallel test execution** (enabled for many test categories)
7. **Predictive Test Selection** (enabled for eligible test categories)

## Performance Tuning Guide

### For Local Development

Use default settings or enable file watching for incremental builds:
```bash
./gradlew build --watch-fs
```

### For CI/CD

Use default settings which are optimized for CI environments.

### For Resource-Constrained Environments

Reduce parallelism and memory:
```bash
./gradlew build -PmaxTestForks=2 -PtestMaxHeap=2g
```

### For High-Performance Servers

Increase parallelism:
```bash
./gradlew build -PmaxTestForks=16 -PtestMaxHeap=4g
```

## Measuring Impact

To measure the impact of these optimizations:

1. **Build Scan**: Enable Develocity build scans to see detailed performance metrics
2. **Time comparison**: Compare build times before and after optimizations
3. **Memory usage**: Monitor system memory usage during builds
4. **CPU utilization**: Check CPU usage to ensure good parallelization

## Additional Optimization Opportunities

Future optimizations that could be considered:

1. **Remote build cache**: Already configured via Develocity
2. **Test distribution**: Consider Develocity Test Distribution for even faster test execution
3. **Dependency resolution**: Consider using dependency locking for faster resolution
4. **Compiler optimizations**: Already using ErrorProne and incremental compilation
5. **Build parallelization**: Already enabled at project level

## Rollback Instructions

If these optimizations cause issues, you can revert to previous settings:

```bash
# Restore previous test forking frequency
./gradlew build -PtestForkEvery=2000

# Restore previous max heap
./gradlew build -PtestMaxHeap=6g

# Restore previous parallel forks
./gradlew build -PmaxTestForks=8

# Or edit gradle.properties and gradle/tests.gradle to restore original values
```
