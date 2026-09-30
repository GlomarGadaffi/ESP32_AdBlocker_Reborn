/*
 * Minimal driver so a fuzz target can be built WITHOUT libFuzzer (plain gcc
 * + ASan/UBSan) to reproduce a crash file or run a corpus directory once:
 *
 *   gcc -O1 -g -fsanitize=address,undefined -I ../../main \
 *       fuzz_dns_wire.c standalone_main.c ../../main/dns_wire.c \
 *       ../../main/domain.c -o repro && ./repro crashes/crash-xxxx
 *
 * Each argument is a file (fed whole) or a directory (every regular file in
 * it is fed). Modeled on compiler-rt's StandaloneFuzzTargetMain.c.
 */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return 1; }
    uint8_t *buf = (uint8_t *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return 1; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    fprintf(stderr, "Running: %s (%zu bytes)\n", path, got);
    LLVMFuzzerTestOneInput(buf, got);
    fprintf(stderr, "Done:    %s\n", path);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        struct stat st;
        if (stat(argv[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            DIR *d = opendir(argv[i]);
            if (!d) { perror(argv[i]); rc = 1; continue; }
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                if (e->d_name[0] == '.') continue;
                char p[4096];
                snprintf(p, sizeof(p), "%s/%s", argv[i], e->d_name);
                if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) rc |= run_file(p);
            }
            closedir(d);
        } else {
            rc |= run_file(argv[i]);
        }
    }
    return rc;
}
