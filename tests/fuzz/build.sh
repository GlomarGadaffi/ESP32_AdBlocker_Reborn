#!/bin/sh
# Build the fuzz targets. Honors the OSS-Fuzz / ClusterFuzzLite contract:
#   $CC, $CFLAGS, $LIB_FUZZING_ENGINE, $OUT, $SRC are used when set,
# so this same script is what a future .clusterfuzzlite/build.sh would call.
#
# Local use (WSL, clang with compiler-rt):
#   CC=~/llvm/bin/clang sh tests/fuzz/build.sh
#   ./tests/fuzz/out/fuzz_dns_wire tests/fuzz/corpus/dns_wire -max_len=1500
#   ./tests/fuzz/out/fuzz_rule_parse tests/fuzz/corpus/rule_parse -max_len=512
#
# Local use without libFuzzer (plain gcc + sanitizers, corpus replay only):
#   FUZZ_STANDALONE=1 sh tests/fuzz/build.sh
#   ./tests/fuzz/out/fuzz_dns_wire tests/fuzz/corpus/dns_wire
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${CC:=clang}"
: "${OUT:=$here/out}"
: "${SRC:=$root}"
mkdir -p "$OUT"

if [ "${FUZZ_STANDALONE:-0}" = "1" ]; then
    : "${CFLAGS:=-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined}"
    set -- "$here/standalone_main.c"
else
    : "${CFLAGS:=-O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined}"
    : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
    # shellcheck disable=SC2086
    set -- $LIB_FUZZING_ENGINE
fi

# shellcheck disable=SC2086
$CC $CFLAGS -I"$SRC/main" -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION "$here/fuzz_rule_parse.c" \
    "$SRC/main/domain.c" "$SRC/main/murmur3.c" \
    "$@" -o "$OUT/fuzz_rule_parse"
# shellcheck disable=SC2086
$CC $CFLAGS -I"$SRC/main" -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION "$here/fuzz_dns_wire.c" \
    "$SRC/main/dns_wire.c" "$SRC/main/domain.c" "$SRC/main/murmur3.c" \
    "$@" -o "$OUT/fuzz_dns_wire"
# shellcheck disable=SC2086
$CC $CFLAGS -I"$SRC/main" -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION "$here/fuzz_web_parse.c" "$SRC/main/web_parse.c" \
    "$@" -o "$OUT/fuzz_web_parse"

# Seed corpora ship zipped for OSS-Fuzz-style runners; locally the plain dirs
# under corpus/ are used directly.
if command -v zip >/dev/null 2>&1; then
    for t in rule_parse dns_wire web_parse; do
        (cd "$here/corpus/$t" && zip -q -r "$OUT/fuzz_${t}_seed_corpus.zip" .) || true
    done
fi
echo "built: $OUT/fuzz_rule_parse $OUT/fuzz_dns_wire $OUT/fuzz_web_parse"
