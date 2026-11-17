#!/bin/sh
# Build and run every host unit test listed in tests/host_tests.txt under
# ASan + UBSan. Usage: sh tests/run_host_tests.sh [test_name]
# Exit 1 if any test fails, a listed source is missing, or no test ran.
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
manifest="$here/host_tests.txt"
only=${1:-}
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$root" || exit 1

pass=0
fail=0
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    name=${line%%:*}
    srcs=${line#*:}
    [ -n "$only" ] && [ "$only" != "$name" ] && continue
    missing=""
    for s in $srcs; do
        [ -f "$s" ] || missing="$missing $s"
    done
    if [ -n "$missing" ]; then
        echo "WARNING: $name: missing source(s):$missing" >&2
        echo "FAIL $name"
        fail=$((fail + 1))
        continue
    fi
    # shellcheck disable=SC2086
    if ${CC:-gcc} -O2 -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined \
            -I main -o "$tmp/$name" $srcs && "$tmp/$name"; then
        echo "PASS $name"
        pass=$((pass + 1))
    else
        echo "FAIL $name"
        fail=$((fail + 1))
    fi
done < "$manifest"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ] && [ "$pass" -gt 0 ]
