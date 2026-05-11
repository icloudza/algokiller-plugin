#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

typedef struct {
    int fd;
    const unsigned char *data;
    size_t size;
} MappedFile;

typedef struct {
    unsigned char *pattern;
    size_t pattern_len;
    unsigned char lower[256];
    size_t skip[256];
} BmhSearcher;

typedef struct {
    const unsigned char *start;
    size_t len;
} LineView;

typedef struct {
    size_t *offsets;
    uint64_t count;
    uint64_t capacity;
} LineIndex;

typedef struct {
    MappedFile mapped;
    LineIndex index;
} IndexedFile;

static void usage(FILE *stream) {
    fprintf(stream,
            "Usage:\n"
            "  ak_search match    --file PATH --query TEXT [--from-line N | --before-line N] [--limit N]\n"
            "  ak_search context  --file PATH --line N [--context N]\n"
            "  ak_search context  --file PATH --line N [--before N] [--after N]\n"
            "  ak_search daemon   --file PATH\n"
            "  ak_search regflow  --file PATH --reg xN [--from-line N] [--to-line N] [--limit N]\n"
            "  ak_search producer --file PATH --value 0xVAL --sink-line N [--max-back N]\n"
            "  ak_search semop    --file PATH (--line N | --from-line N --to-line N) [--limit N]\n"
            "\n"
            "Match mode is ASCII case-insensitive. --before-line searches backward, nearest first.\n"
            "regflow emits one row per line where the target register receives an output value.\n"
            "producer scans backward from --sink-line for the most recent instruction whose\n"
            "  '-> regN=0xVAL' matches --value.\n"
            "semop classifies each instruction (zero, crypto_candidate, hash_loop_candidate,\n"
            "  stack_save/restore, memory_load/store, branch, data_move, addr_calc, alu, ...).\n"
            "Output: one JSON object per line with 1-based line numbers.\n");
}

static bool parse_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

static int map_file(const char *path, MappedFile *mapped) {
    memset(mapped, 0, sizeof(*mapped));
    mapped->fd = -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open failed: %s: %s\n", path, strerror(errno));
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "fstat failed: %s: %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "not a regular file: %s\n", path);
        close(fd);
        return 1;
    }
    if (st.st_size < 0) {
        fprintf(stderr, "invalid file size: %s\n", path);
        close(fd);
        return 1;
    }

    mapped->fd = fd;
    mapped->size = (size_t)st.st_size;
    if (mapped->size == 0) {
        mapped->data = NULL;
        return 0;
    }

    void *ptr = mmap(NULL, mapped->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s: %s\n", path, strerror(errno));
        close(fd);
        mapped->fd = -1;
        return 1;
    }
    mapped->data = (const unsigned char *)ptr;
    return 0;
}

static void unmap_file(MappedFile *mapped) {
    if (mapped->data != NULL && mapped->size > 0) {
        munmap((void *)mapped->data, mapped->size);
    }
    if (mapped->fd >= 0) {
        close(mapped->fd);
    }
    memset(mapped, 0, sizeof(*mapped));
    mapped->fd = -1;
}

static void line_index_destroy(LineIndex *index) {
    if (index->offsets != NULL && index->capacity > 0) {
        size_t bytes = (size_t)index->capacity * sizeof(*index->offsets);
        munmap(index->offsets, bytes);
    }
    memset(index, 0, sizeof(*index));
}

static uint64_t count_line_starts(const MappedFile *mapped) {
    if (mapped->size == 0) {
        return 0;
    }

    uint64_t count = 1;
    const unsigned char *cursor = mapped->data;
    const unsigned char *end = mapped->data + mapped->size;
    while (cursor < end) {
        const unsigned char *newline = memchr(cursor, '\n', (size_t)(end - cursor));
        if (newline == NULL) {
            break;
        }
        if (newline + 1 < end) {
            count++;
        }
        cursor = newline + 1;
    }
    return count;
}

static int line_index_reserve(LineIndex *index, uint64_t capacity) {
    if (capacity == 0) {
        return 0;
    }
    if (capacity > (uint64_t)(SIZE_MAX / sizeof(*index->offsets))) {
        fprintf(stderr, "line index too large\n");
        return 1;
    }

    size_t bytes = (size_t)capacity * sizeof(*index->offsets);
    void *ptr = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "mmap failed while preallocating line index: %s\n", strerror(errno));
        return 1;
    }
    index->offsets = (size_t *)ptr;
    index->capacity = capacity;
    return 0;
}

static int build_line_index(const MappedFile *mapped, LineIndex *index) {
    memset(index, 0, sizeof(*index));
    uint64_t line_count = count_line_starts(mapped);
    if (line_index_reserve(index, line_count) != 0) {
        return 1;
    }
    if (line_count == 0) {
        return 0;
    }

    index->offsets[index->count++] = 0;
    const unsigned char *cursor = mapped->data;
    const unsigned char *end = mapped->data + mapped->size;
    while (cursor < end) {
        const unsigned char *newline = memchr(cursor, '\n', (size_t)(end - cursor));
        if (newline == NULL) {
            break;
        }
        if (newline + 1 < end) {
            index->offsets[index->count++] = (size_t)((newline + 1) - mapped->data);
        }
        cursor = newline + 1;
    }
    return 0;
}

static int indexed_file_open(const char *path, IndexedFile *indexed) {
    memset(indexed, 0, sizeof(*indexed));
    indexed->mapped.fd = -1;
    if (map_file(path, &indexed->mapped) != 0) {
        return 1;
    }
    if (build_line_index(&indexed->mapped, &indexed->index) != 0) {
        unmap_file(&indexed->mapped);
        return 1;
    }
    return 0;
}

static void indexed_file_close(IndexedFile *indexed) {
    line_index_destroy(&indexed->index);
    unmap_file(&indexed->mapped);
}

static bool indexed_line_start(const IndexedFile *indexed, uint64_t line_no, size_t *offset_out) {
    if (line_no == 0 || line_no > indexed->index.count) {
        return false;
    }
    *offset_out = indexed->index.offsets[line_no - 1];
    return true;
}

static void init_ascii_lower(unsigned char lower[256]) {
    for (size_t i = 0; i < 256; i++) {
        lower[i] = (unsigned char)i;
    }
    for (unsigned char c = 'A'; c <= 'Z'; c++) {
        lower[c] = (unsigned char)(c + ('a' - 'A'));
    }
}

static int bmh_init(BmhSearcher *searcher, const char *query) {
    size_t len = strlen(query);
    memset(searcher, 0, sizeof(*searcher));
    init_ascii_lower(searcher->lower);

    searcher->pattern = malloc(len == 0 ? 1 : len);
    if (searcher->pattern == NULL) {
        fprintf(stderr, "malloc failed while preparing search pattern\n");
        return 1;
    }
    searcher->pattern_len = len;
    for (size_t i = 0; i < len; i++) {
        searcher->pattern[i] = searcher->lower[(unsigned char)query[i]];
    }

    for (size_t i = 0; i < 256; i++) {
        searcher->skip[i] = len == 0 ? 1 : len;
    }
    if (len > 1) {
        for (size_t i = 0; i + 1 < len; i++) {
            searcher->skip[searcher->pattern[i]] = len - 1 - i;
        }
    }
    return 0;
}

static void bmh_destroy(BmhSearcher *searcher) {
    free(searcher->pattern);
    memset(searcher, 0, sizeof(*searcher));
}

static bool folded_equal_at(const BmhSearcher *searcher,
                            const unsigned char *haystack,
                            size_t needle_len) {
    for (size_t i = 0; i < needle_len; i++) {
        if (searcher->lower[haystack[i]] != searcher->pattern[i]) {
            return false;
        }
    }
    return true;
}

static const unsigned char *bmh_find(const BmhSearcher *searcher,
                                     const unsigned char *haystack,
                                     size_t haystack_len) {
    size_t needle_len = searcher->pattern_len;
    if (needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }
    if (needle_len == 1) {
        for (size_t i = 0; i < haystack_len; i++) {
            if (searcher->lower[haystack[i]] == searcher->pattern[0]) {
                return haystack + i;
            }
        }
        return NULL;
    }

    size_t pos = 0;
    while (pos <= haystack_len - needle_len) {
        unsigned char last = searcher->lower[haystack[pos + needle_len - 1]];
        if (last == searcher->pattern[needle_len - 1] &&
            folded_equal_at(searcher, haystack + pos, needle_len)) {
            return haystack + pos;
        }
        pos += searcher->skip[last];
    }
    return NULL;
}

static LineView line_at_offset(const unsigned char *data, size_t size, size_t offset) {
    LineView line;
    line.start = data + offset;
    line.len = 0;

    size_t end = offset;
    while (end < size && data[end] != '\n') {
        end++;
    }
    line.len = end - offset;
    if (line.len > 0 && line.start[line.len - 1] == '\r') {
        line.len--;
    }
    return line;
}

static bool next_line_start(const MappedFile *mapped, size_t offset, size_t *next_offset_out) {
    if (offset >= mapped->size) {
        return false;
    }

    const unsigned char *start = mapped->data + offset;
    const unsigned char *end = mapped->data + mapped->size;
    const unsigned char *newline = memchr(start, '\n', (size_t)(end - start));
    if (newline == NULL || newline + 1 >= end) {
        return false;
    }

    *next_offset_out = (size_t)((newline + 1) - mapped->data);
    return true;
}

static bool prev_line_start(const MappedFile *mapped, size_t offset, size_t *prev_offset_out) {
    if (offset == 0 || mapped->size == 0) {
        return false;
    }

    size_t pos = offset - 1;
    while (pos > 0) {
        pos--;
        if (mapped->data[pos] == '\n') {
            *prev_offset_out = pos + 1;
            return true;
        }
    }

    *prev_offset_out = 0;
    return true;
}

static bool direct_line_start(const MappedFile *mapped,
                              uint64_t target_line,
                              uint64_t *line_no_out,
                              size_t *offset_out) {
    if (mapped->size == 0 || target_line == 0) {
        return false;
    }

    uint64_t line_no = 1;
    size_t offset = 0;
    while (line_no < target_line) {
        size_t next_offset = 0;
        if (!next_line_start(mapped, offset, &next_offset)) {
            return false;
        }
        offset = next_offset;
        line_no++;
    }

    *line_no_out = line_no;
    *offset_out = offset;
    return true;
}

static void direct_last_line_start(const MappedFile *mapped,
                                   uint64_t *line_no_out,
                                   size_t *offset_out) {
    uint64_t line_no = 1;
    size_t offset = 0;
    while (true) {
        size_t next_offset = 0;
        if (!next_line_start(mapped, offset, &next_offset)) {
            break;
        }
        offset = next_offset;
        line_no++;
    }

    *line_no_out = line_no;
    *offset_out = offset;
}

static void json_write_string(const unsigned char *text, size_t len) {
    putchar('"');
    for (size_t i = 0; i < len; i++) {
        unsigned char c = text[i];
        switch (c) {
            case '"':
                fputs("\\\"", stdout);
                break;
            case '\\':
                fputs("\\\\", stdout);
                break;
            case '\b':
                fputs("\\b", stdout);
                break;
            case '\f':
                fputs("\\f", stdout);
                break;
            case '\n':
                fputs("\\n", stdout);
                break;
            case '\r':
                fputs("\\r", stdout);
                break;
            case '\t':
                fputs("\\t", stdout);
                break;
            default:
                if (c < 0x20) {
                    printf("\\u%04x", c);
                } else {
                    putchar((int)c);
                }
                break;
        }
    }
    putchar('"');
}

static void json_write_cstr(const char *text) {
    json_write_string((const unsigned char *)text, strlen(text));
}

static void emit_line(const char *type,
                      uint64_t line_no,
                      uint64_t byte_offset,
                      bool is_target,
                      LineView line) {
    printf("{\"type\":\"%s\",\"line\":%" PRIu64 ",\"byte_offset\":%" PRIu64,
           type,
           line_no,
           byte_offset);
    if (is_target) {
        fputs(",\"target\":true", stdout);
    }
    fputs(",\"text\":", stdout);
    json_write_string(line.start, line.len);
    fputs("}\n", stdout);
}

static int emit_daemon_end(const char *status, const char *error) {
    fputs("{\"type\":\"daemon_end\",\"status\":", stdout);
    json_write_cstr(status);
    if (error != NULL && error[0] != '\0') {
        fputs(",\"error\":", stdout);
        json_write_cstr(error);
    }
    fputs("}\n", stdout);
    fflush(stdout);
    return strcmp(status, "ok") == 0 ? 0 : 1;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char *hex_decode_to_cstr(const char *hex) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return NULL;
    }
    size_t out_len = hex_len / 2;
    char *out = malloc(out_len + 1);
    if (out == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            free(out);
            return NULL;
        }
        out[i] = (char)((hi << 4) | lo);
    }
    out[out_len] = '\0';
    return out;
}

static int run_match_forward(const IndexedFile *indexed,
                             const char *query,
                             uint64_t from_line,
                             uint64_t limit) {
    if (limit == 0 || indexed->mapped.size == 0 || from_line > indexed->index.count) {
        return 0;
    }

    BmhSearcher searcher;
    if (bmh_init(&searcher, query) != 0) {
        return 1;
    }

    uint64_t emitted = 0;
    for (uint64_t line_no = from_line; line_no <= indexed->index.count && emitted < limit; line_no++) {
        size_t offset = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, offset);
        if (bmh_find(&searcher, line.start, line.len) != NULL) {
            emit_line("match", line_no, (uint64_t)offset, false, line);
            emitted++;
        }
    }

    bmh_destroy(&searcher);
    return 0;
}

static int run_match_backward(const IndexedFile *indexed,
                              const char *query,
                              uint64_t before_line,
                              uint64_t limit) {
    if (limit == 0 || indexed->mapped.size == 0 || before_line <= 1) {
        return 0;
    }

    uint64_t line_no = before_line - 1;
    if (line_no > indexed->index.count) {
        line_no = indexed->index.count;
    }

    BmhSearcher searcher;
    if (bmh_init(&searcher, query) != 0) {
        return 1;
    }

    uint64_t emitted = 0;
    while (line_no >= 1 && emitted < limit) {
        size_t offset = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, offset);
        if (bmh_find(&searcher, line.start, line.len) != NULL) {
            emit_line("match", line_no, (uint64_t)offset, false, line);
            emitted++;
        }
        if (line_no == 1) {
            break;
        }
        line_no--;
    }

    bmh_destroy(&searcher);
    return 0;
}

static int run_context(const IndexedFile *indexed,
                       uint64_t target_line,
                       uint64_t before,
                       uint64_t after) {
    if (indexed->mapped.size == 0) {
        return 0;
    }

    uint64_t first_line = target_line > before ? target_line - before : 1;
    uint64_t last_line = UINT64_MAX - target_line < after ? UINT64_MAX : target_line + after;
    if (last_line > indexed->index.count) {
        last_line = indexed->index.count;
    }

    size_t offset = 0;
    if (!indexed_line_start(indexed, first_line, &offset)) {
        return 0;
    }

    for (uint64_t line_no = first_line; line_no <= last_line; line_no++) {
        offset = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, offset);
        emit_line("context", line_no, (uint64_t)offset, line_no == target_line, line);
    }
    return 0;
}

static int run_match_forward_direct(const MappedFile *mapped,
                                    const char *query,
                                    uint64_t from_line,
                                    uint64_t limit) {
    if (limit == 0 || mapped->size == 0) {
        return 0;
    }

    uint64_t line_no = 0;
    size_t offset = 0;
    if (!direct_line_start(mapped, from_line, &line_no, &offset)) {
        return 0;
    }

    BmhSearcher searcher;
    if (bmh_init(&searcher, query) != 0) {
        return 1;
    }

    uint64_t emitted = 0;
    while (emitted < limit) {
        LineView line = line_at_offset(mapped->data, mapped->size, offset);
        if (bmh_find(&searcher, line.start, line.len) != NULL) {
            emit_line("match", line_no, (uint64_t)offset, false, line);
            emitted++;
        }

        size_t next_offset = 0;
        if (!next_line_start(mapped, offset, &next_offset)) {
            break;
        }
        offset = next_offset;
        line_no++;
    }

    bmh_destroy(&searcher);
    return 0;
}

static int run_match_backward_direct(const MappedFile *mapped,
                                     const char *query,
                                     uint64_t before_line,
                                     uint64_t limit) {
    if (limit == 0 || mapped->size == 0 || before_line <= 1) {
        return 0;
    }

    uint64_t line_no = 0;
    size_t offset = 0;
    uint64_t anchor_line = 0;
    size_t anchor_offset = 0;
    if (direct_line_start(mapped, before_line, &anchor_line, &anchor_offset)) {
        if (!prev_line_start(mapped, anchor_offset, &offset)) {
            return 0;
        }
        line_no = anchor_line - 1;
    } else {
        direct_last_line_start(mapped, &line_no, &offset);
    }

    BmhSearcher searcher;
    if (bmh_init(&searcher, query) != 0) {
        return 1;
    }

    uint64_t emitted = 0;
    while (line_no >= 1 && emitted < limit) {
        LineView line = line_at_offset(mapped->data, mapped->size, offset);
        if (bmh_find(&searcher, line.start, line.len) != NULL) {
            emit_line("match", line_no, (uint64_t)offset, false, line);
            emitted++;
        }
        if (line_no == 1) {
            break;
        }

        size_t prev_offset = 0;
        if (!prev_line_start(mapped, offset, &prev_offset)) {
            break;
        }
        offset = prev_offset;
        line_no--;
    }

    bmh_destroy(&searcher);
    return 0;
}

static int run_context_direct(const MappedFile *mapped,
                              uint64_t target_line,
                              uint64_t before,
                              uint64_t after) {
    if (mapped->size == 0) {
        return 0;
    }

    uint64_t first_line = target_line > before ? target_line - before : 1;
    uint64_t last_line = UINT64_MAX - target_line < after ? UINT64_MAX : target_line + after;

    uint64_t line_no = 0;
    size_t offset = 0;
    if (!direct_line_start(mapped, first_line, &line_no, &offset)) {
        return 0;
    }

    while (line_no <= last_line) {
        LineView line = line_at_offset(mapped->data, mapped->size, offset);
        emit_line("context", line_no, (uint64_t)offset, line_no == target_line, line);

        size_t next_offset = 0;
        if (!next_line_start(mapped, offset, &next_offset)) {
            break;
        }
        offset = next_offset;
        line_no++;
    }
    return 0;
}

/* ===========================================================================
 * Sprint 1 extensions: regflow / producer / semop
 *
 * regflow   — emit register output-value sequence for a target register
 *             over a line range. Uses the GumTrace " -> regN=0xVAL " pattern.
 *
 * producer  — find the most recent line that wrote a given value to any
 *             register, scanning backward from a sink line. Reduces multi-step
 *             "before_line + bisect" loops the agent does manually.
 *
 * semop     — classify each instruction's semantic role (zero / crypto_candidate
 *             / hash_loop_candidate / stack_save|restore / memory_load|store /
 *             branch / data_move / addr_calc / alu / unknown). Lets the agent
 *             prune non-crypto candidates before deep dive.
 * ===========================================================================
 */

static const unsigned char *mem_find(const unsigned char *h, size_t hlen,
                                     const unsigned char *n, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(h + i, n, nlen) == 0) return h + i;
    }
    return NULL;
}

/* parse_hex_run - read "0x" + hex chars starting at pos, write into out (NUL-term).
 * Returns ptr just past the last hex digit on success, NULL on failure.
 */
static const unsigned char *parse_hex_run(const unsigned char *pos,
                                          const unsigned char *end,
                                          char *out, size_t out_sz) {
    if (end - pos < 2 || pos[0] != '0' || pos[1] != 'x') return NULL;
    if (out_sz < 3) return NULL;
    out[0] = '0'; out[1] = 'x';
    size_t i = 2;
    const unsigned char *p = pos + 2;
    while (p < end && i + 1 < out_sz) {
        unsigned char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) break;
        out[i++] = (char)c;
        p++;
    }
    if (i == 2) return NULL;
    out[i] = '\0';
    return p;
}

/* Extract the value written to a specific register on a line, by parsing the
 * "-> regKey0xVAL" portion. regKey example: "x0=" (caller supplies the `=`).
 * Returns true and fills out_val on success.
 */
static bool extract_output_value(LineView line, const char *reg_key,
                                 char *out_val, size_t out_val_sz) {
    static const unsigned char arrow[] = " -> ";
    const unsigned char *a = mem_find(line.start, line.len, arrow, 4);
    if (a == NULL) return false;
    const unsigned char *region = a + 4;
    const unsigned char *end = line.start + line.len;
    size_t klen = strlen(reg_key);
    for (const unsigned char *p = region; p + klen <= end; p++) {
        /* require space or arrow boundary before key */
        if (p > region && p[-1] != ' ') continue;
        if (memcmp(p, reg_key, klen) != 0) continue;
        return parse_hex_run(p + klen, end, out_val, out_val_sz) != NULL;
    }
    return false;
}

/* Find any "-> <reg>=<wanted_value>" on a line; return matched register name in
 * out_reg (e.g. "x7"). Used by producer search.
 */
static bool find_output_reg_for_value(LineView line, const char *wanted_value,
                                      char *out_reg, size_t out_reg_sz) {
    static const unsigned char arrow[] = " -> ";
    const unsigned char *a = mem_find(line.start, line.len, arrow, 4);
    if (a == NULL) return false;
    const unsigned char *region = a + 4;
    const unsigned char *end = line.start + line.len;
    /* Scan tokens of form "<reg>=0xVAL " */
    const unsigned char *p = region;
    while (p < end) {
        while (p < end && *p == ' ') p++;
        const unsigned char *tok_start = p;
        while (p < end && *p != '=' && *p != ' ') p++;
        if (p >= end || *p != '=') break;
        const unsigned char *eq = p;
        p++;
        char val_buf[64];
        const unsigned char *after = parse_hex_run(p, end, val_buf, sizeof(val_buf));
        if (after == NULL) { p++; continue; }
        if (strcmp(val_buf, wanted_value) == 0) {
            size_t reg_len = (size_t)(eq - tok_start);
            if (reg_len + 1 > out_reg_sz) return false;
            memcpy(out_reg, tok_start, reg_len);
            out_reg[reg_len] = '\0';
            return true;
        }
        p = after;
    }
    return false;
}

/* Parse mnemonic + operand region from a line of form:
 *   [WeChat] 0xABS!0xREL mnem operands; ...
 * Returns false if line doesn't match the expected GumTrace prefix.
 */
static bool parse_mnem_and_operands(LineView line,
                                    const unsigned char **mnem_start, size_t *mnem_len,
                                    const unsigned char **op_start, size_t *op_len) {
    if (line.len == 0 || line.start[0] != '[') return false;
    const unsigned char *bang = mem_find(line.start, line.len, (const unsigned char *)"!", 1);
    if (bang == NULL) return false;
    const unsigned char *end = line.start + line.len;
    const unsigned char *space = NULL;
    for (const unsigned char *q = bang; q < end; q++) {
        if (*q == ' ') { space = q; break; }
    }
    if (space == NULL) return false;
    const unsigned char *m = space + 1;
    if (m >= end) return false;
    const unsigned char *m_end = m;
    while (m_end < end && *m_end != ' ' && *m_end != ';') m_end++;
    *mnem_start = m;
    *mnem_len = (size_t)(m_end - m);
    const unsigned char *o = m_end;
    if (o < end && *o == ' ') o++;
    const unsigned char *semi = NULL;
    for (const unsigned char *q = o; q < end; q++) {
        if (*q == ';') { semi = q; break; }
    }
    const unsigned char *o_end = semi != NULL ? semi : end;
    *op_start = o;
    *op_len = o_end > o ? (size_t)(o_end - o) : 0;
    return true;
}

/* Classify an instruction by mnemonic + operand pattern. */
static const char *classify_semop(const unsigned char *mnem, size_t mnem_len,
                                  const unsigned char *op, size_t op_len) {
    /* branch family */
    if (mnem_len >= 1 && mnem[0] == 'b') {
        if (mnem_len == 1) return "branch";
        if (mnem_len == 2 && (mnem[1] == 'l' || mnem[1] == 'r')) return "branch";
        if (mnem_len == 3 && memcmp(mnem, "blr", 3) == 0) return "branch";
        if (mnem_len >= 3 && memcmp(mnem, "b.", 2) == 0) return "branch";
    }
    if (mnem_len == 3 && (memcmp(mnem, "cbz", 3) == 0 || memcmp(mnem, "ret", 3) == 0)) return "branch";
    if (mnem_len == 4 && memcmp(mnem, "cbnz", 4) == 0) return "branch";
    if (mnem_len == 3 && (memcmp(mnem, "tbz", 3) == 0)) return "branch";
    if (mnem_len == 4 && (memcmp(mnem, "tbnz", 4) == 0)) return "branch";

    /* stp / ldp: stack save/restore vs generic memory */
    if (mnem_len == 3 && memcmp(mnem, "stp", 3) == 0) {
        if (mem_find(op, op_len, (const unsigned char *)"x29, x30", 8) != NULL ||
            mem_find(op, op_len, (const unsigned char *)"fp, lr", 6) != NULL ||
            mem_find(op, op_len, (const unsigned char *)"[sp", 3) != NULL) {
            return "stack_save";
        }
        return "memory_store";
    }
    if (mnem_len == 3 && memcmp(mnem, "ldp", 3) == 0) {
        if (mem_find(op, op_len, (const unsigned char *)"x29, x30", 8) != NULL ||
            mem_find(op, op_len, (const unsigned char *)"fp, lr", 6) != NULL ||
            mem_find(op, op_len, (const unsigned char *)"[sp", 3) != NULL) {
            return "stack_restore";
        }
        return "memory_load";
    }

    /* madd / msub — Bernstein / DJB / FNV-style polynomial accumulators */
    if (mnem_len == 4 && (memcmp(mnem, "madd", 4) == 0 || memcmp(mnem, "msub", 4) == 0)) {
        return "hash_loop_candidate";
    }
    if (mnem_len == 5 && (memcmp(mnem, "smaddl", 6) == 0)) return "hash_loop_candidate";

    /* eor / xor — distinguish zero-self vs crypto candidate */
    if (mnem_len == 3 && (memcmp(mnem, "eor", 3) == 0 || memcmp(mnem, "xor", 3) == 0)) {
        char regs[3][32] = {{0}};
        int reg_idx = 0;
        size_t reg_len = 0;
        for (size_t i = 0; i < op_len && reg_idx < 3; i++) {
            unsigned char ch = op[i];
            if (ch == ',' || ch == ' ') {
                if (reg_len > 0) {
                    regs[reg_idx][reg_len] = '\0';
                    reg_idx++;
                    reg_len = 0;
                }
            } else {
                if (reg_len + 1 < sizeof(regs[0])) {
                    regs[reg_idx][reg_len++] = (char)ch;
                }
            }
        }
        if (reg_len > 0 && reg_idx < 3) regs[reg_idx][reg_len] = '\0';
        if (regs[0][0] && regs[1][0] && regs[2][0] &&
            strcmp(regs[0], regs[1]) == 0 && strcmp(regs[1], regs[2]) == 0) {
            return "zero";
        }
        return "crypto_candidate";
    }

    /* memory loads/stores */
    if (mnem_len >= 3 && memcmp(mnem, "ldr", 3) == 0) return "memory_load";
    if (mnem_len >= 3 && memcmp(mnem, "str", 3) == 0) return "memory_store";
    if (mnem_len == 4 && (memcmp(mnem, "ldur", 4) == 0)) return "memory_load";
    if (mnem_len == 4 && (memcmp(mnem, "stur", 4) == 0)) return "memory_store";

    /* address calc */
    if (mnem_len == 4 && memcmp(mnem, "adrp", 4) == 0) return "addr_calc";
    if (mnem_len == 3 && memcmp(mnem, "adr", 3) == 0) return "addr_calc";

    /* data movement */
    if (mnem_len >= 3 && memcmp(mnem, "mov", 3) == 0) return "data_move";

    /* ALU */
    if (mnem_len == 3 && (memcmp(mnem, "add", 3) == 0 || memcmp(mnem, "sub", 3) == 0 ||
                          memcmp(mnem, "and", 3) == 0 || memcmp(mnem, "orr", 3) == 0 ||
                          memcmp(mnem, "mul", 3) == 0 || memcmp(mnem, "neg", 3) == 0 ||
                          memcmp(mnem, "lsl", 3) == 0 || memcmp(mnem, "lsr", 3) == 0 ||
                          memcmp(mnem, "asr", 3) == 0 || memcmp(mnem, "ror", 3) == 0)) {
        return "alu";
    }

    /* compare */
    if (mnem_len == 3 && (memcmp(mnem, "cmp", 3) == 0 || memcmp(mnem, "tst", 3) == 0)) return "compare";
    if (mnem_len == 4 && memcmp(mnem, "subs", 4) == 0) return "compare";

    return "unknown";
}

static void emit_regflow(uint64_t line_no, const char *value, LineView line) {
    fputs("{\"type\":\"regflow\",\"line\":", stdout);
    printf("%" PRIu64, line_no);
    fputs(",\"value\":", stdout);
    json_write_cstr(value);
    fputs(",\"instr\":", stdout);
    json_write_string(line.start, line.len);
    fputs("}\n", stdout);
}

static void emit_producer(uint64_t line_no, const char *reg, const char *value, LineView line) {
    fputs("{\"type\":\"producer\",\"line\":", stdout);
    printf("%" PRIu64, line_no);
    fputs(",\"reg\":", stdout);
    json_write_cstr(reg);
    fputs(",\"value\":", stdout);
    json_write_cstr(value);
    fputs(",\"instr\":", stdout);
    json_write_string(line.start, line.len);
    fputs("}\n", stdout);
}

static void emit_semop(uint64_t line_no, const unsigned char *mnem, size_t mnem_len,
                       const char *klass, const unsigned char *op, size_t op_len,
                       LineView line) {
    fputs("{\"type\":\"semop\",\"line\":", stdout);
    printf("%" PRIu64, line_no);
    fputs(",\"mnem\":", stdout);
    json_write_string(mnem, mnem_len);
    fputs(",\"class\":", stdout);
    json_write_cstr(klass);
    fputs(",\"operands\":", stdout);
    json_write_string(op, op_len);
    fputs(",\"instr\":", stdout);
    json_write_string(line.start, line.len);
    fputs("}\n", stdout);
}

static int run_regflow(const IndexedFile *indexed, const char *reg,
                       uint64_t from_line, uint64_t to_line, uint64_t limit) {
    if (limit == 0 || indexed->mapped.size == 0) return 0;
    if (from_line == 0) from_line = 1;
    if (to_line == 0 || to_line > indexed->index.count) to_line = indexed->index.count;
    if (from_line > to_line) return 0;

    char reg_key[40];
    snprintf(reg_key, sizeof(reg_key), "%s=", reg);

    uint64_t emitted = 0;
    char value[64];
    for (uint64_t line_no = from_line; line_no <= to_line && emitted < limit; line_no++) {
        size_t offset = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, offset);
        if (extract_output_value(line, reg_key, value, sizeof(value))) {
            emit_regflow(line_no, value, line);
            emitted++;
        }
    }
    return 0;
}

static int run_producer(const IndexedFile *indexed, const char *value,
                        uint64_t sink_line, uint64_t max_back) {
    if (indexed->mapped.size == 0 || sink_line <= 1) return 0;
    if (sink_line - 1 > indexed->index.count) sink_line = indexed->index.count + 1;
    uint64_t start = sink_line - 1;
    uint64_t end = (max_back == 0 || max_back >= start) ? 1 : start - max_back + 1;

    char reg[32];
    for (uint64_t line_no = start; line_no >= end; line_no--) {
        size_t offset = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, offset);
        if (find_output_reg_for_value(line, value, reg, sizeof(reg))) {
            emit_producer(line_no, reg, value, line);
            return 0;
        }
        if (line_no == 1) break;
    }
    return 0;
}

static int run_semop_range(const IndexedFile *indexed, uint64_t from_line,
                           uint64_t to_line, uint64_t limit) {
    if (limit == 0 || indexed->mapped.size == 0) return 0;
    if (from_line == 0) from_line = 1;
    if (to_line == 0 || to_line > indexed->index.count) to_line = indexed->index.count;
    if (from_line > to_line) return 0;

    uint64_t emitted = 0;
    for (uint64_t line_no = from_line; line_no <= to_line && emitted < limit; line_no++) {
        size_t offset = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, offset);
        const unsigned char *mnem, *op;
        size_t mnem_len, op_len;
        if (!parse_mnem_and_operands(line, &mnem, &mnem_len, &op, &op_len)) continue;
        const char *klass = classify_semop(mnem, mnem_len, op, op_len);
        emit_semop(line_no, mnem, mnem_len, klass, op, op_len, line);
        emitted++;
    }
    return 0;
}

static int cmd_regflow(int argc, char **argv) {
    const char *path = NULL;
    const char *reg = NULL;
    uint64_t from_line = 0, to_line = 0, limit = 100;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--reg") == 0 && i + 1 < argc) reg = argv[++i];
        else if (strcmp(argv[i], "--from-line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &from_line)) { fprintf(stderr, "invalid --from-line\n"); return 2; }
        }
        else if (strcmp(argv[i], "--to-line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &to_line)) { fprintf(stderr, "invalid --to-line\n"); return 2; }
        }
        else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &limit)) { fprintf(stderr, "invalid --limit\n"); return 2; }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL || reg == NULL || reg[0] == '\0') { usage(stderr); return 2; }

    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_regflow(&indexed, reg, from_line, to_line, limit);
    indexed_file_close(&indexed);
    return result;
}

static int cmd_producer(int argc, char **argv) {
    const char *path = NULL;
    const char *value = NULL;
    uint64_t sink_line = 0, max_back = 100000;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) value = argv[++i];
        else if (strcmp(argv[i], "--sink-line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &sink_line) || sink_line == 0) {
                fprintf(stderr, "invalid --sink-line\n"); return 2;
            }
        }
        else if (strcmp(argv[i], "--max-back") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &max_back)) { fprintf(stderr, "invalid --max-back\n"); return 2; }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL || value == NULL || value[0] == '\0' || sink_line == 0) {
        usage(stderr); return 2;
    }

    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_producer(&indexed, value, sink_line, max_back);
    indexed_file_close(&indexed);
    return result;
}

static int cmd_semop(int argc, char **argv) {
    const char *path = NULL;
    uint64_t line = 0, from_line = 0, to_line = 0, limit = 100;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &line)) { fprintf(stderr, "invalid --line\n"); return 2; }
        }
        else if (strcmp(argv[i], "--from-line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &from_line)) { fprintf(stderr, "invalid --from-line\n"); return 2; }
        }
        else if (strcmp(argv[i], "--to-line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &to_line)) { fprintf(stderr, "invalid --to-line\n"); return 2; }
        }
        else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &limit)) { fprintf(stderr, "invalid --limit\n"); return 2; }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL) { usage(stderr); return 2; }
    if (line == 0 && from_line == 0 && to_line == 0) {
        fprintf(stderr, "semop requires --line, or --from-line + --to-line\n");
        return 2;
    }
    if (line != 0) { from_line = line; to_line = line; }

    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_semop_range(&indexed, from_line, to_line, limit);
    indexed_file_close(&indexed);
    return result;
}

static int cmd_match(int argc, char **argv) {
    const char *path = NULL;
    const char *query = NULL;
    uint64_t from_line = 1;
    uint64_t before_line = 0;
    uint64_t limit = 20;
    bool has_from_line = false;
    bool has_before_line = false;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--query") == 0 && i + 1 < argc) {
            query = argv[++i];
        } else if (strcmp(argv[i], "--from-line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &from_line) || from_line == 0) {
                fprintf(stderr, "invalid --from-line\n");
                return 2;
            }
            has_from_line = true;
        } else if (strcmp(argv[i], "--before-line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &before_line) || before_line == 0) {
                fprintf(stderr, "invalid --before-line\n");
                return 2;
            }
            has_before_line = true;
        } else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &limit)) {
                fprintf(stderr, "invalid --limit\n");
                return 2;
            }
        } else {
            usage(stderr);
            return 2;
        }
    }

    if (path == NULL || query == NULL || query[0] == '\0') {
        usage(stderr);
        return 2;
    }
    if (has_from_line && has_before_line) {
        fprintf(stderr, "--from-line and --before-line are mutually exclusive\n");
        return 2;
    }
    if (limit == 0) {
        return 0;
    }

    MappedFile mapped;
    if (map_file(path, &mapped) != 0) {
        return 1;
    }

    int result = has_before_line
        ? run_match_backward_direct(&mapped, query, before_line, limit)
        : run_match_forward_direct(&mapped, query, from_line, limit);
    unmap_file(&mapped);
    return result;
}

static int cmd_context(int argc, char **argv) {
    const char *path = NULL;
    uint64_t target_line = 0;
    uint64_t before = 0;
    uint64_t after = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &target_line) || target_line == 0) {
                fprintf(stderr, "invalid --line\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) {
            uint64_t context = 0;
            if (!parse_u64(argv[++i], &context)) {
                fprintf(stderr, "invalid --context\n");
                return 2;
            }
            before = context;
            after = context;
        } else if (strcmp(argv[i], "--before") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &before)) {
                fprintf(stderr, "invalid --before\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--after") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &after)) {
                fprintf(stderr, "invalid --after\n");
                return 2;
            }
        } else {
            usage(stderr);
            return 2;
        }
    }

    if (path == NULL || target_line == 0) {
        usage(stderr);
        return 2;
    }

    MappedFile mapped;
    if (map_file(path, &mapped) != 0) {
        return 1;
    }

    int result = run_context_direct(&mapped, target_line, before, after);
    unmap_file(&mapped);
    return result;
}

static int handle_daemon_match(const IndexedFile *indexed, char **parts, int count) {
    if (count != 5) {
        return emit_daemon_end("error", "invalid match command");
    }

    uint64_t from_line = 0;
    uint64_t before_line = 0;
    uint64_t limit = 0;
    if (!parse_u64(parts[1], &from_line) ||
        !parse_u64(parts[2], &before_line) ||
        !parse_u64(parts[3], &limit)) {
        return emit_daemon_end("error", "invalid numeric match argument");
    }
    if ((from_line == 0 && before_line == 0) || (from_line != 0 && before_line != 0)) {
        return emit_daemon_end("error", "match requires exactly one of from_line or before_line");
    }

    char *query = hex_decode_to_cstr(parts[4]);
    if (query == NULL || query[0] == '\0') {
        free(query);
        return emit_daemon_end("error", "invalid or empty query");
    }

    int result = before_line != 0
        ? run_match_backward(indexed, query, before_line, limit)
        : run_match_forward(indexed, query, from_line, limit);
    free(query);
    if (result != 0) {
        return emit_daemon_end("error", "match failed");
    }
    return emit_daemon_end("ok", NULL);
}

static int handle_daemon_context(const IndexedFile *indexed, char **parts, int count) {
    if (count != 4) {
        return emit_daemon_end("error", "invalid context command");
    }

    uint64_t line = 0;
    uint64_t before = 0;
    uint64_t after = 0;
    if (!parse_u64(parts[1], &line) ||
        !parse_u64(parts[2], &before) ||
        !parse_u64(parts[3], &after) ||
        line == 0) {
        return emit_daemon_end("error", "invalid numeric context argument");
    }

    int result = run_context(indexed, line, before, after);
    if (result != 0) {
        return emit_daemon_end("error", "context failed");
    }
    return emit_daemon_end("ok", NULL);
}

static int cmd_daemon(int argc, char **argv) {
    const char *path = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else {
            usage(stderr);
            return 2;
        }
    }

    if (path == NULL) {
        usage(stderr);
        return 2;
    }

    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) {
        return 1;
    }

    printf("{\"type\":\"daemon_ready\",\"status\":\"ok\",\"line_count\":%" PRIu64 "}\n", indexed.index.count);
    fflush(stdout);

    char command[65536];
    while (fgets(command, sizeof(command), stdin) != NULL) {
        size_t len = strlen(command);
        while (len > 0 && (command[len - 1] == '\n' || command[len - 1] == '\r')) {
            command[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }
        if (strcmp(command, "quit") == 0) {
            break;
        }

        char *parts[6] = {0};
        int count = 0;
        char *saveptr = NULL;
        char *token = strtok_r(command, "\t", &saveptr);
        while (token != NULL && count < 6) {
            parts[count++] = token;
            token = strtok_r(NULL, "\t", &saveptr);
        }
        if (token != NULL) {
            emit_daemon_end("error", "too many command fields");
            continue;
        }

        if (count > 0 && strcmp(parts[0], "match") == 0) {
            handle_daemon_match(&indexed, parts, count);
        } else if (count > 0 && strcmp(parts[0], "context") == 0) {
            handle_daemon_context(&indexed, parts, count);
        } else {
            emit_daemon_end("error", "unknown daemon command");
        }
    }

    indexed_file_close(&indexed);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (strcmp(argv[1], "match") == 0) {
        return cmd_match(argc, argv);
    }
    if (strcmp(argv[1], "context") == 0) {
        return cmd_context(argc, argv);
    }
    if (strcmp(argv[1], "daemon") == 0) {
        return cmd_daemon(argc, argv);
    }
    if (strcmp(argv[1], "regflow") == 0) {
        return cmd_regflow(argc, argv);
    }
    if (strcmp(argv[1], "producer") == 0) {
        return cmd_producer(argc, argv);
    }
    if (strcmp(argv[1], "semop") == 0) {
        return cmd_semop(argc, argv);
    }
    usage(stderr);
    return 2;
}
