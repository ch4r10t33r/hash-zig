#!/bin/bash
# Benchmark script for lifetime 2^18

echo "Running benchmark for Lifetime 2^18..."
echo ""

zig build test-lifetimes 2>&1 | awk '
BEGIN {
    in_lifetime_2_18 = 0
    epoch_count = 0
}
/Testing Lifetime: 2\^18/ {
    in_lifetime_2_18 = 1
    epoch_count = 0
    delete sign_times
    delete verify_times
    delete epochs
}
in_lifetime_2_18 && /Key Generation Time:/ {
    # Extract seconds - look for number before " seconds"
    for (i=1; i<=NF; i++) {
        if ($i == "seconds") {
            keygen_s = $(i-1)
            break
        }
    }
    # Extract milliseconds - look for number before " ms)"
    for (i=1; i<=NF; i++) {
        if ($i ~ /ms\)/) {
            keygen_ms = $(i-1)
            gsub(/\(/, "", keygen_ms)  # Remove opening parenthesis if present
            break
        }
    }
}
in_lifetime_2_18 && /✅ Epoch/ {
    epoch_count++
    # Extract epoch number
    epoch = $0
    gsub(/.*Epoch /, "", epoch)
    gsub(/:.*/, "", epoch)
    epochs[epoch_count] = epoch
    
    # Extract sign time
    sign = $0
    gsub(/.*Sign=/, "", sign)
    gsub(/ms.*/, "", sign)
    sign_times[epoch_count] = sign + 0
    
    # Extract verify time
    verify = $0
    gsub(/.*Verify=/, "", verify)
    gsub(/ms.*/, "", verify)
    verify_times[epoch_count] = verify + 0
}
in_lifetime_2_18 && /✅ All tests passed for lifetime 2\^18/ {
    print ""
    print "============================================================"
    print "LIFETIME 2^18 PERFORMANCE METRICS"
    print "============================================================"
    print ""
    print "Key Generation:"
    printf "  Time: %s seconds (%s ms)\n", keygen_s, keygen_ms
    print ""
    print "Signing Performance (" epoch_count " epochs):"
    sum_sign = 0
    min_sign = 999999
    max_sign = 0
    min_epoch_idx = 0
    max_epoch_idx = 0
    for (i=1; i<=epoch_count; i++) {
        sum_sign += sign_times[i]
        if (sign_times[i] < min_sign) {
            min_sign = sign_times[i]
            min_epoch_idx = i
        }
        if (sign_times[i] > max_sign) {
            max_sign = sign_times[i]
            max_epoch_idx = i
        }
    }
    avg_sign = sum_sign / epoch_count
    printf "  Average: %.3f ms\n", avg_sign
    printf "  Min:     %.3f ms (epoch %s)\n", min_sign, epochs[min_epoch_idx]
    printf "  Max:     %.3f ms (epoch %s)\n", max_sign, epochs[max_epoch_idx]
    print ""
    print "Verification Performance (" epoch_count " epochs):"
    sum_verify = 0
    min_verify = 999999
    max_verify = 0
    for (i=1; i<=epoch_count; i++) {
        sum_verify += verify_times[i]
        if (verify_times[i] < min_verify) min_verify = verify_times[i]
        if (verify_times[i] > max_verify) max_verify = verify_times[i]
    }
    avg_verify = sum_verify / epoch_count
    printf "  Average: %.3f ms\n", avg_verify
    printf "  Min:     %.3f ms\n", min_verify
    printf "  Max:     %.3f ms\n", max_verify
    print ""
    print "============================================================"
    exit
}
'

