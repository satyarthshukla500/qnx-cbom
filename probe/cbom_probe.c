/*
 * cbom_probe.c - lists the crypto libraries each process has mapped (QNX 8.0).
 *
 * For every process in /proc it reads the memory map (the same devctl calls
 * pidin uses), picks the mapped files named libcrypto*, libssl*, libqcrypto*
 * or qcrypto-*, and reads the OpenSSL version banner from each file.
 * It only reads; the one file it writes is the one named with -o.
 *
 * usage: cbom_probe [-p pid] [-o file] [-s]
 *   no option  JSON between CBOM-BEGIN / CBOM-END lines on standard output
 *   -p pid     look at one process only
 *   -o file    write plain JSON to file
 *   -s         serve the JSON at /dev/cbom (resource manager)
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <devctl.h>

#define PROBE_VERSION "0.1.0"
#define MAX_JSON (4u * 1024 * 1024)
#define MAX_PROCESSES 4096
#define MAX_MAPS 8192
#define MAX_LIBS_PER_PROCESS 64
#define MAX_LIB_FILE (64u * 1024 * 1024)
#define CHUNK 65536
#define OVERLAP 64

/* ---- growable text buffer with a hard size limit ---- */

struct text {
    char *data;
    size_t len;
    size_t cap;
    int failed;
};

static void text_init(struct text *t)
{
    t->data = NULL;
    t->len = 0;
    t->cap = 0;
    t->failed = 0;
}

static void text_free(struct text *t)
{
    free(t->data);
    text_init(t);
}

static void text_add(struct text *t, const char *s, size_t n)
{
    if (t->failed) {
        return;
    }
    if (n > MAX_JSON || t->len + n + 1 > MAX_JSON) {
        t->failed = 1;
        return;
    }
    if (t->len + n + 1 > t->cap) {
        size_t cap = t->cap ? t->cap : 1024;
        while (cap < t->len + n + 1) {
            cap *= 2;
        }
        char *bigger = realloc(t->data, cap);
        if (bigger == NULL) {
            t->failed = 1;
            return;
        }
        t->data = bigger;
        t->cap = cap;
    }
    memcpy(t->data + t->len, s, n);
    t->len += n;
    t->data[t->len] = '\0';
}

static void text_puts(struct text *t, const char *s)
{
    text_add(t, s, strlen(s));
}

static void text_printf_int(struct text *t, long long value)
{
    char tmp[32];
    int n = snprintf(tmp, sizeof tmp, "%lld", value);
    if (n > 0 && (size_t)n < sizeof tmp) {
        text_add(t, tmp, (size_t)n);
    }
}

/* JSON string: quotes, backslashes and bytes outside printable ASCII are escaped */
static void text_json_string(struct text *t, const char *s)
{
    static const char hex[] = "0123456789abcdef";
    text_add(t, "\"", 1);
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            char two[2] = { '\\', (char)c };
            text_add(t, two, 2);
        } else if (c < 0x20 || c >= 0x7f) {
            char esc[6] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] };
            text_add(t, esc, 6);
        } else {
            char one = (char)c;
            text_add(t, &one, 1);
        }
    }
    text_add(t, "\"", 1);
}

/* ---- crc32 (same as zlib) so a console capture can be checked on the host ---- */

static uint32_t crc32_of(const char *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (unsigned char)data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

/* ---- reading a library file: version banner and post-quantum names ---- */

struct libinfo {
    char version[32];
    char released[16];
    int pq_capable;
};

/* release date text like "25 Aug 2026" (1-2 digits, 3 letters, 4 digits) */
static int valid_date(const unsigned char *p, size_t avail, size_t *used)
{
    size_t i = 0;
    while (i < avail && i < 2 && isdigit(p[i])) {
        i++;
    }
    if (i == 0 || avail < i + 10 || p[i] != ' ' || !isupper(p[i + 1]) || !islower(p[i + 2]) || !islower(p[i + 3]) ||
        p[i + 4] != ' ' || !isdigit(p[i + 5]) || !isdigit(p[i + 6]) || !isdigit(p[i + 7]) || !isdigit(p[i + 8])) {
        return 0;
    }
    *used = i + 9;
    return 1;
}

/* "OpenSSL 3.0.22 25 Aug 2026": returns 1 and fills version/released when text at p matches */
static int parse_banner(const unsigned char *p, size_t avail, struct libinfo *out)
{
    size_t i = 8;
    size_t v = 0;
    size_t used = 0;
    int dots = 0;
    if (avail < 32 || memcmp(p, "OpenSSL ", 8) != 0) {
        return 0;
    }
    while (i < avail && v + 1 < sizeof out->version && (isdigit(p[i]) || p[i] == '.')) {
        dots += (p[i] == '.');
        out->version[v++] = (char)p[i++];
    }
    if (i + 1 < avail && v + 1 < sizeof out->version && islower(p[i]) && p[i + 1] == ' ') {
        out->version[v++] = (char)p[i++];
    }
    out->version[v] = '\0';
    if (dots != 2 || i >= avail || p[i] != ' ' || !valid_date(p + i + 1, avail - i - 1, &used) || used >= sizeof out->released) {
        out->version[0] = '\0';
        return 0;
    }
    memcpy(out->released, p + i + 1, used);
    out->released[used] = '\0';
    return 1;
}

static int has_pq_name(const unsigned char *p, size_t avail)
{
    static const char *const names[] = { "ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA" };
    for (size_t k = 0; k < sizeof names / sizeof names[0]; k++) {
        size_t n = strlen(names[k]);
        if (avail >= n && memcmp(p, names[k], n) == 0) {
            return 1;
        }
    }
    return 0;
}

/* returns 0 on success, -1 with errno set when the file cannot be read */
static int read_library(const char *path, struct libinfo *info)
{
    unsigned char *buf = malloc(CHUNK + OVERLAP + 1);
    size_t carry = 0;
    size_t total = 0;
    struct stat st;
    int fd;
    memset(info, 0, sizeof *info);
    if (buf == NULL) {
        errno = ENOMEM;
        return -1;
    }
    /* no blocking open (a fifo put in place of the file must not stop the scan) and regular files only */
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))) {
        close(fd);
        fd = -1;
        errno = EINVAL;
    }
    if (fd < 0) {
        free(buf);
        return -1;
    }
    for (;;) {
        ssize_t got = read(fd, buf + carry, CHUNK);
        size_t n;
        size_t stop;
        if (got < 0) {
            int saved = errno;
            close(fd);
            free(buf);
            errno = saved;
            return -1;
        }
        n = carry + (size_t)got;
        total += (size_t)got;
        /* positions closer than OVERLAP to the end are checked with the next chunk */
        stop = (got == 0 || total >= MAX_LIB_FILE) ? n : (n > OVERLAP ? n - OVERLAP : 0);
        for (size_t i = 0; i < stop; i++) {
            if (info->version[0] == '\0' && buf[i] == 'O') {
                parse_banner(buf + i, n - i, info);
            } else if (!info->pq_capable && (buf[i] == 'M' || buf[i] == 'S')) {
                info->pq_capable = has_pq_name(buf + i, n - i);
            }
        }
        if (got == 0 || total >= MAX_LIB_FILE) {
            break;
        }
        carry = n - stop;
        memmove(buf, buf + stop, carry);
    }
    close(fd);
    free(buf);
    return 0;
}

/* ---- one process ---- */

struct mapped_path {
    char path[PATH_MAX];
};

static int is_crypto_name(const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strncmp(base, "libcrypto", 9) == 0 || strncmp(base, "libssl", 6) == 0 ||
           strncmp(base, "libqcrypto", 10) == 0 || strncmp(base, "qcrypto-", 8) == 0;
}

static void add_error(struct text *errors, int *count, long pid, const char *what, int err)  /* err: errno or devctl result */
{
    char msg[160];
    if (*count > 0) {
        text_puts(errors, ",");
    }
    snprintf(msg, sizeof msg, "%s: errno %d", what, err);
    text_puts(errors, "{\"pid\":");
    text_printf_int(errors, pid);
    text_puts(errors, ",\"what\":");
    text_json_string(errors, msg);
    text_puts(errors, "}");
    (*count)++;
}

/* path of the mapping that starts at vaddr; 0 on success */
static int map_path(int fd, uint64_t vaddr, char *out, size_t outsz)
{
    struct {
        procfs_debuginfo info;
        char buff[PATH_MAX];
    } dbg;
    memset(&dbg, 0, sizeof dbg);
    dbg.info.vaddr = vaddr;
    if (devctl(fd, DCMD_PROC_MAPDEBUG, &dbg, sizeof dbg, NULL) != EOK) {
        return -1;
    }
    dbg.buff[sizeof dbg.buff - 1] = '\0';
    snprintf(out, outsz, "%s", dbg.info.path);
    return 0;
}

/* appends {"pid":..,"name":..,"libs":[..]} to out when the process maps a crypto library */
static void probe_process(long pid, struct text *out, int *listed, struct text *errors, int *error_count)
{
    char proc_as[64];
    char name[PATH_MAX];
    procfs_info pinfo;
    procfs_mapinfo *maps;
    struct mapped_path *seen;
    struct text mine;
    int nmaps = 0;
    int got = 0;
    int rc;
    int nseen = 0;
    int fd;

    snprintf(proc_as, sizeof proc_as, "/proc/%ld/as", pid);
    fd = open(proc_as, O_RDONLY);
    if (fd < 0) {
        add_error(errors, error_count, pid, "open /proc/<pid>/as", errno);
        return;
    }
    memset(&pinfo, 0, sizeof pinfo);
    rc = devctl(fd, DCMD_PROC_INFO, &pinfo, sizeof pinfo, NULL);
    if (rc == EOK) {
        rc = devctl(fd, DCMD_PROC_MAPINFO, NULL, 0, &nmaps);
    }
    if (rc != EOK || nmaps <= 0) {
        add_error(errors, error_count, pid, "read memory map", rc);
        close(fd);
        return;
    }
    if (nmaps > MAX_MAPS) {
        add_error(errors, error_count, pid, "too many memory mappings, process not checked", nmaps);
        close(fd);
        return;
    }
    maps = calloc((size_t)nmaps, sizeof *maps);
    seen = calloc(MAX_LIBS_PER_PROCESS, sizeof *seen);
    rc = (maps != NULL && seen != NULL) ? devctl(fd, DCMD_PROC_MAPINFO, maps, (size_t)nmaps * sizeof *maps, &got) : ENOMEM;
    if (rc != EOK) {
        add_error(errors, error_count, pid, "read memory map", rc);
        free(maps);
        free(seen);
        close(fd);
        return;
    }
    if (got > nmaps) {
        got = nmaps;
    }
    if (map_path(fd, pinfo.base_address, name, sizeof name) != 0) {
        snprintf(name, sizeof name, "?");
    }
    text_init(&mine);
    for (int i = 0; i < got; i++) {
        char path[PATH_MAX];
        struct libinfo info;
        int duplicate = 0;
        if (!(maps[i].flags & MAP_ELF) || map_path(fd, maps[i].vaddr, path, sizeof path) != 0 || !is_crypto_name(path)) {
            continue;
        }
        for (int k = 0; k < nseen; k++) {
            duplicate = duplicate || strcmp(seen[k].path, path) == 0;
        }
        if (duplicate) {
            continue;
        }
        if (nseen >= MAX_LIBS_PER_PROCESS) {
            add_error(errors, error_count, pid, "more crypto libraries than the probe lists", nseen);
            break;
        }
        snprintf(seen[nseen++].path, sizeof seen[0].path, "%s", path);
        if (read_library(path, &info) != 0) {
            add_error(errors, error_count, pid, "read mapped library", errno);
            memset(&info, 0, sizeof info);
        }
        const char *base = strrchr(path, '/');
        text_puts(&mine, nseen > 1 ? ",{\"path\":" : "{\"path\":");
        text_json_string(&mine, path);
        text_puts(&mine, ",\"soname\":");
        text_json_string(&mine, base ? base + 1 : path);
        text_puts(&mine, ",\"version\":");
        if (info.version[0]) {
            text_json_string(&mine, info.version);
        } else {
            text_puts(&mine, "null");
        }
        text_puts(&mine, ",\"released\":");
        if (info.released[0]) {
            text_json_string(&mine, info.released);
        } else {
            text_puts(&mine, "null");
        }
        text_puts(&mine, info.pq_capable ? ",\"pq_capable\":true}" : ",\"pq_capable\":false}");
    }
    if (mine.failed) {
        out->failed = 1;
    }
    if (nseen > 0) {
        text_puts(out, *listed ? ",{\"pid\":" : "{\"pid\":");
        text_printf_int(out, pid);
        text_puts(out, ",\"name\":");
        text_json_string(out, name);
        text_puts(out, ",\"libs\":[");
        text_add(out, mine.data ? mine.data : "", mine.len);
        text_puts(out, "]}");
        (*listed)++;
    }
    text_free(&mine);
    free(maps);
    free(seen);
    close(fd);
}

/* whole report; pid_only < 0 means all processes. Returns 0 on success. */
static int make_report(long pid_only, struct text *out)
{
    struct text procs, errors;
    struct utsname un;
    int listed = 0;
    int error_count = 0;
    int scanned = 0;

    text_init(&procs);
    text_init(&errors);
    if (pid_only >= 0) {
        probe_process(pid_only, &procs, &listed, &errors, &error_count);
        scanned = 1;
    } else {
        DIR *dir = opendir("/proc");
        struct dirent *entry;
        if (dir == NULL) {
            return -1;
        }
        while ((entry = readdir(dir)) != NULL && scanned < MAX_PROCESSES) {
            char *end = NULL;
            long pid = strtol(entry->d_name, &end, 10);
            if (end == entry->d_name || *end != '\0' || pid <= 0) {
                continue;
            }
            scanned++;
            probe_process(pid, &procs, &listed, &errors, &error_count);
        }
        closedir(dir);
    }
    memset(&un, 0, sizeof un);
    if (uname(&un) != 0) {
        snprintf(un.sysname, sizeof un.sysname, "unknown");
    }
    if (scanned >= MAX_PROCESSES) {
        add_error(&errors, &error_count, 0, "process limit reached, later processes not checked", scanned);
    }
    text_puts(out, "{\"schema\":\"qnx-cbom-probe/1\",\"probe_version\":\"" PROBE_VERSION "\",\"target\":{\"sysname\":");
    text_json_string(out, un.sysname);
    text_puts(out, ",\"release\":");
    text_json_string(out, un.release);
    text_puts(out, ",\"machine\":");
    text_json_string(out, un.machine);
    text_puts(out, "},\"scanned\":");
    text_printf_int(out, scanned);
    text_puts(out, ",\"processes\":[");
    text_add(out, procs.data ? procs.data : "", procs.len);
    text_puts(out, "],\"errors\":[");
    text_add(out, errors.data ? errors.data : "", errors.len);
    text_puts(out, "]}");
    text_free(&procs);
    text_free(&errors);
    return (out->failed || procs.failed || errors.failed) ? -1 : 0;
}

#ifdef CBOM_WITH_RESMGR
#include "cbom_resmgr.h"
#endif

static int write_file(const char *path, const struct text *json)
{
    /* owner-only file (the report lists every process that uses crypto); an existing file must be
       a regular file we own with no other links, so a link or fifo cannot be used to damage something else */
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
    size_t done = 0;
    struct stat st;
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != geteuid() ||
        fchmod(fd, 0600) != 0 || ftruncate(fd, 0) != 0) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    while (done < json->len) {
        ssize_t n = write(fd, json->data + done, json->len - done);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    return close(fd);
}

int main(int argc, char **argv)
{
    long pid_only = -1;
    const char *out_file = NULL;
    int serve = 0;
    int opt;
    struct text json;

    while ((opt = getopt(argc, argv, "p:o:sh")) != -1) {
        char *end = NULL;
        switch (opt) {
        case 'p':
            pid_only = strtol(optarg, &end, 10);
            if (*optarg == '\0' || *end != '\0' || pid_only <= 0) {
                fprintf(stderr, "cbom_probe: bad pid: %s\n", optarg);
                return 2;
            }
            break;
        case 'o':
            out_file = optarg;
            break;
        case 's':
            serve = 1;
            break;
        default:
            fprintf(stderr, "usage: cbom_probe [-p pid] [-o file] [-s]\n");
            return opt == 'h' ? 0 : 2;
        }
    }
    if (serve) {
#ifdef CBOM_WITH_RESMGR
        return serve_resmgr();
#else
        fprintf(stderr, "cbom_probe: built without resource manager support\n");
        return 2;
#endif
    }
    text_init(&json);
    if (make_report(pid_only, &json) != 0) {
        fprintf(stderr, "cbom_probe: could not build the report\n");
        text_free(&json);
        return 1;
    }
    if (out_file != NULL) {
        if (write_file(out_file, &json) != 0) {
            fprintf(stderr, "cbom_probe: cannot write %s: errno %d\n", out_file, errno);
            text_free(&json);
            return 1;
        }
    } else {
        if (printf("CBOM-BEGIN\n%s\nCBOM-END len=%zu crc32=%08x\n", json.data, json.len, (unsigned)crc32_of(json.data, json.len)) < 0 ||
            fflush(stdout) != 0) {
            fprintf(stderr, "cbom_probe: cannot write to standard output\n");
            text_free(&json);
            return 1;
        }
    }
    text_free(&json);
    return 0;
}
