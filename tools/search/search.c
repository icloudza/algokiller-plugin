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
            "  ak_search lint      --file PATH [--top N]\n"
            "  ak_search fold      --in PATH --out PATH [--threshold N] [--block N]\n"
            "  ak_search callgraph --file PATH (--to NAME | --top N) [--limit N]\n"
            "  ak_search modgraph  --file PATH [--top N]\n"
            "  ak_search hexblock  --file PATH --line N [--max-lines N]\n"
            "  ak_search constscan   --file PATH [--samples N]\n"
            "  ak_search bytes       --file PATH --query 0xVAL [--limit N] [--with-text]\n"
            "  ak_search cryptoinstr --file PATH [--samples N]\n"
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
 *   [Module] 0xABS!0xREL mnem operands; ...
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

/* ===========================================================================
 * Sprint 2 extensions: lint / fold
 *
 * lint  — single-pass scan of a trace, emit a JSON summary: line count,
 *         module distribution, top mnemonics, call-func block count,
 *         presence of register/memory observations. Run before bind_trace
 *         to confirm the file is a usable GumTrace-format capture.
 *
 * fold  — write a derivative trace with long runs of identical-signature
 *         instructions (same mnemonic + same operands) collapsed to first
 *         line + sentinel + last line. Reduces 110 MB hash-loop traces to
 *         ~20 MB without losing data-flow boundary evidence.
 * ===========================================================================
 */

typedef struct {
    char name[96];
    uint64_t count;
} CountEntry;

typedef struct {
    CountEntry *entries;
    size_t count;
    size_t capacity;
} CountTable;

static void count_table_init(CountTable *tbl) {
    tbl->entries = NULL;
    tbl->count = 0;
    tbl->capacity = 0;
}

static void count_table_free(CountTable *tbl) {
    free(tbl->entries);
    tbl->entries = NULL;
    tbl->count = 0;
    tbl->capacity = 0;
}

static int count_table_bump(CountTable *tbl, const unsigned char *name, size_t name_len) {
    if (name_len >= sizeof(tbl->entries[0].name)) {
        name_len = sizeof(tbl->entries[0].name) - 1;
    }
    for (size_t i = 0; i < tbl->count; i++) {
        if (strlen(tbl->entries[i].name) == name_len &&
            memcmp(tbl->entries[i].name, name, name_len) == 0) {
            tbl->entries[i].count++;
            return 0;
        }
    }
    if (tbl->count == tbl->capacity) {
        size_t new_cap = tbl->capacity == 0 ? 32 : tbl->capacity * 2;
        CountEntry *nx = realloc(tbl->entries, new_cap * sizeof(CountEntry));
        if (nx == NULL) return -1;
        tbl->entries = nx;
        tbl->capacity = new_cap;
    }
    memcpy(tbl->entries[tbl->count].name, name, name_len);
    tbl->entries[tbl->count].name[name_len] = '\0';
    tbl->entries[tbl->count].count = 1;
    tbl->count++;
    return 0;
}

static int count_entry_cmp_desc(const void *a, const void *b) {
    uint64_t ca = ((const CountEntry *)a)->count;
    uint64_t cb = ((const CountEntry *)b)->count;
    if (ca < cb) return 1;
    if (ca > cb) return -1;
    return 0;
}

/* Parse just the "[module]" prefix of a line. Returns (start, len) into the
 * tag content (between '[' and ']'), or false if line doesn't start with '['.
 */
static bool parse_module_tag(LineView line,
                             const unsigned char **tag_start, size_t *tag_len) {
    if (line.len < 2 || line.start[0] != '[') return false;
    const unsigned char *end = line.start + line.len;
    const unsigned char *close = NULL;
    for (const unsigned char *p = line.start + 1; p < end; p++) {
        if (*p == ']') { close = p; break; }
        if (*p == ' ') return false;  /* missing close bracket */
    }
    if (close == NULL) return false;
    *tag_start = line.start + 1;
    *tag_len = (size_t)(close - (line.start + 1));
    return true;
}

/* Scan a line for "<reg>=0x" patterns. Returns true if at least one is found.
 * Caller passes scratch buffer for one-shot regex-free probe.
 */
static bool line_has_reg_eq_hex(LineView line) {
    const unsigned char *end = line.start + line.len;
    for (const unsigned char *p = line.start; p + 4 < end; p++) {
        /* Look for "xN=" or "wN=" or "spN=" boundary */
        if ((*p == 'x' || *p == 'w') && p > line.start && (p[-1] == ' ' || p[-1] == '>')) {
            const unsigned char *q = p + 1;
            while (q < end && *q >= '0' && *q <= '9') q++;
            if (q > p + 1 && q + 3 < end && *q == '=' && q[1] == '0' && q[2] == 'x') {
                return true;
            }
        }
    }
    return false;
}

static int run_lint(const IndexedFile *indexed, uint64_t top_k) {
    CountTable modules; count_table_init(&modules);
    CountTable mnemonics; count_table_init(&mnemonics);

    uint64_t call_func_count = 0;
    uint64_t hexdump_count = 0;
    uint64_t ret_marker_count = 0;
    uint64_t lines_with_mod_tag = 0;
    uint64_t lines_with_reg_obs = 0;
    uint64_t lines_with_mem_r = 0;
    uint64_t lines_with_mem_w = 0;
    uint64_t blank_lines = 0;
    uint64_t total_text_bytes = 0;

    const unsigned char call_prefix[] = "call func:";
    const unsigned char hex_prefix[] = "hexdump at";
    const unsigned char ret_prefix[] = "ret:";
    const unsigned char mem_r_token[] = "mem_r=";
    const unsigned char mem_w_token[] = "mem_w=";

    for (uint64_t line_no = 1; line_no <= indexed->index.count; line_no++) {
        size_t offset = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, offset);
        total_text_bytes += line.len;
        if (line.len == 0) { blank_lines++; continue; }

        const unsigned char *mod_tag = NULL;
        size_t mod_tag_len = 0;
        if (parse_module_tag(line, &mod_tag, &mod_tag_len)) {
            lines_with_mod_tag++;
            count_table_bump(&modules, mod_tag, mod_tag_len);

            const unsigned char *mnem, *op;
            size_t mnem_len, op_len;
            if (parse_mnem_and_operands(line, &mnem, &mnem_len, &op, &op_len)) {
                count_table_bump(&mnemonics, mnem, mnem_len);
            }

            if (line_has_reg_eq_hex(line)) lines_with_reg_obs++;
            if (mem_find(line.start, line.len, mem_r_token, sizeof(mem_r_token) - 1) != NULL) {
                lines_with_mem_r++;
            }
            if (mem_find(line.start, line.len, mem_w_token, sizeof(mem_w_token) - 1) != NULL) {
                lines_with_mem_w++;
            }
        } else if (line.len >= sizeof(call_prefix) - 1 &&
                   memcmp(line.start, call_prefix, sizeof(call_prefix) - 1) == 0) {
            call_func_count++;
        } else if (line.len >= sizeof(hex_prefix) - 1 &&
                   memcmp(line.start, hex_prefix, sizeof(hex_prefix) - 1) == 0) {
            hexdump_count++;
        } else if (line.len >= sizeof(ret_prefix) - 1 &&
                   memcmp(line.start, ret_prefix, sizeof(ret_prefix) - 1) == 0) {
            ret_marker_count++;
        }
    }

    qsort(modules.entries, modules.count, sizeof(CountEntry), count_entry_cmp_desc);
    qsort(mnemonics.entries, mnemonics.count, sizeof(CountEntry), count_entry_cmp_desc);

    uint64_t total = indexed->index.count;
    uint64_t mod_emit = modules.count < top_k ? modules.count : top_k;
    uint64_t mnem_emit = mnemonics.count < top_k ? mnemonics.count : top_k;

    fputs("{\"type\":\"lint\"", stdout);
    printf(",\"size_bytes\":%" PRIu64, (uint64_t)indexed->mapped.size);
    printf(",\"line_count\":%" PRIu64, total);
    if (total > 0) {
        printf(",\"avg_line_len\":%" PRIu64, total_text_bytes / total);
    } else {
        fputs(",\"avg_line_len\":0", stdout);
    }
    printf(",\"blank_lines\":%" PRIu64, blank_lines);
    printf(",\"lines_with_module_tag\":%" PRIu64, lines_with_mod_tag);
    printf(",\"call_func_blocks\":%" PRIu64, call_func_count);
    printf(",\"hexdump_blocks\":%" PRIu64, hexdump_count);
    printf(",\"ret_markers\":%" PRIu64, ret_marker_count);
    printf(",\"has_register_observations\":%s", lines_with_reg_obs > 0 ? "true" : "false");
    printf(",\"register_obs_lines\":%" PRIu64, lines_with_reg_obs);
    printf(",\"has_memory_reads\":%s", lines_with_mem_r > 0 ? "true" : "false");
    printf(",\"memory_read_lines\":%" PRIu64, lines_with_mem_r);
    printf(",\"has_memory_writes\":%s", lines_with_mem_w > 0 ? "true" : "false");
    printf(",\"memory_write_lines\":%" PRIu64, lines_with_mem_w);

    fputs(",\"top_modules\":[", stdout);
    for (uint64_t i = 0; i < mod_emit; i++) {
        if (i > 0) putchar(',');
        fputs("{\"name\":", stdout);
        json_write_cstr(modules.entries[i].name);
        printf(",\"lines\":%" PRIu64, modules.entries[i].count);
        if (total > 0) {
            double frac = (double)modules.entries[i].count / (double)total;
            printf(",\"fraction\":%.4f", frac);
        }
        putchar('}');
    }
    fputs("]", stdout);

    fputs(",\"top_mnemonics\":[", stdout);
    for (uint64_t i = 0; i < mnem_emit; i++) {
        if (i > 0) putchar(',');
        fputs("{\"mnem\":", stdout);
        json_write_cstr(mnemonics.entries[i].name);
        printf(",\"count\":%" PRIu64, mnemonics.entries[i].count);
        if (total > 0) {
            double frac = (double)mnemonics.entries[i].count / (double)total;
            printf(",\"fraction\":%.4f", frac);
        }
        putchar('}');
    }
    fputs("]", stdout);

    bool format_ok = (total > 0) && (lines_with_mod_tag * 2 >= total);
    fputs(",\"format_ok\":", stdout);
    fputs(format_ok ? "true" : "false", stdout);

    fputs(",\"warnings\":[", stdout);
    bool first_warn = true;
    if (total == 0) {
        if (!first_warn) putchar(',');
        json_write_cstr("trace file has zero lines");
        first_warn = false;
    }
    if (total > 0 && !format_ok) {
        if (!first_warn) putchar(',');
        json_write_cstr("fewer than 50% of lines look like '[module] 0xABS!0xREL mnem ...' — likely not GumTrace format");
        first_warn = false;
    }
    if (total > 0 && call_func_count == 0) {
        if (!first_warn) putchar(',');
        json_write_cstr("no 'call func:' blocks — ciphertext-mode hexdump tracing will be limited");
        first_warn = false;
    }
    if (total > 0 && lines_with_reg_obs == 0) {
        if (!first_warn) putchar(',');
        json_write_cstr("no register observations (xN=0x...) — register-flow analysis unavailable");
        first_warn = false;
    }
    (void)first_warn;
    fputs("]}\n", stdout);

    count_table_free(&modules);
    count_table_free(&mnemonics);
    return 0;
}

/* extract_line_signature - build a "<mnem> <operands>" string from a line.
 * Returns false if the line doesn't have the [mod] 0xABS!0xREL prefix.
 */
static bool extract_line_signature(LineView line, char *out, size_t out_sz) {
    const unsigned char *m, *o;
    size_t mlen, olen;
    if (!parse_mnem_and_operands(line, &m, &mlen, &o, &olen)) return false;
    if (mlen + 1 + olen + 1 > out_sz) {
        /* Truncate to fit; equality compare will then bucket truncated runs
         * together — acceptable since signatures this long don't realistically
         * appear in ARM64 trace lines.
         */
        size_t cap = out_sz - 1;
        size_t take_m = mlen < cap ? mlen : cap;
        memcpy(out, m, take_m);
        cap -= take_m;
        if (cap > 0) { out[take_m] = ' '; cap--; take_m++; }
        size_t take_o = olen < cap ? olen : cap;
        memcpy(out + take_m, o, take_o);
        out[take_m + take_o] = '\0';
        return true;
    }
    memcpy(out, m, mlen);
    out[mlen] = ' ';
    memcpy(out + mlen + 1, o, olen);
    size_t total = mlen + 1 + olen;
    while (total > 0 && out[total - 1] == ' ') total--;
    out[total] = '\0';
    return true;
}

static void fold_flush_run(const IndexedFile *indexed, FILE *out,
                           uint64_t run_first, uint64_t run_last,
                           const char *signature, uint64_t threshold,
                           uint64_t *fold_count, uint64_t *skipped_lines) {
    if (run_first == 0) return;
    uint64_t cnt = run_last - run_first + 1;
    if (cnt < threshold || cnt < 3) {
        /* expand: write every original line */
        for (uint64_t i = run_first; i <= run_last; i++) {
            size_t off = indexed->index.offsets[i - 1];
            LineView lv = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
            fwrite(lv.start, 1, lv.len, out);
            fputc('\n', out);
        }
        return;
    }
    /* fold: first + sentinel + last */
    size_t off_first = indexed->index.offsets[run_first - 1];
    LineView first_lv = line_at_offset(indexed->mapped.data, indexed->mapped.size, off_first);
    fwrite(first_lv.start, 1, first_lv.len, out);
    fputc('\n', out);
    fprintf(out, "# ak_fold: skipped %" PRIu64 " identical lines (op=\"%s\", first=%" PRIu64 ", last=%" PRIu64 ")\n",
            cnt - 2, signature, run_first, run_last);
    size_t off_last = indexed->index.offsets[run_last - 1];
    LineView last_lv = line_at_offset(indexed->mapped.data, indexed->mapped.size, off_last);
    fwrite(last_lv.start, 1, last_lv.len, out);
    fputc('\n', out);
    (*fold_count)++;
    *skipped_lines += (cnt - 2);
}

/* FNV-1a 64-bit hash of mnem+operands signature, or 0 for non-instruction lines. */
static uint64_t line_signature_hash(LineView line) {
    const unsigned char *m, *o;
    size_t mlen, olen;
    if (!parse_mnem_and_operands(line, &m, &mlen, &o, &olen)) return 0;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < mlen; i++) {
        h ^= m[i];
        h *= 0x100000001b3ULL;
    }
    h ^= ' ';
    h *= 0x100000001b3ULL;
    for (size_t i = 0; i < olen; i++) {
        h ^= o[i];
        h *= 0x100000001b3ULL;
    }
    if (h == 0) h = 1;  /* reserve 0 for "no signature" */
    return h;
}

static void write_line_no_n(const IndexedFile *indexed, FILE *out, uint64_t line_no) {
    size_t off = indexed->index.offsets[line_no - 1];
    LineView lv = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
    fwrite(lv.start, 1, lv.len, out);
    fputc('\n', out);
}

/* Block-aware fold: for each window W, find consecutive line stretches where
 * the W-block ending at line i is identical (signature-wise) to the W-block
 * ending at line i-W. Such a stretch means the W-block is repeating.
 *
 * Algorithm (linear): precompute signature hash per line; then walk a sliding
 * cursor — at each position i, see how far hashes[i..] matches hashes[i+W..]
 * (the next-block shift). The full repeated span covers [i, i+W+match-1].
 *
 * If the span contains >= threshold repetitions of the W-block, emit:
 *   - the first W block lines (original prologue)
 *   - one sentinel comment
 *   - the last W block lines (original epilogue, showing final accumulator state)
 * else emit lines verbatim.
 */
static int run_fold_block(const IndexedFile *indexed, FILE *out,
                          uint64_t threshold, uint64_t window) {
    uint64_t N = indexed->index.count;
    if (N == 0) {
        fprintf(stdout, "{\"type\":\"fold_summary\",\"folds_applied\":0,"
                        "\"lines_skipped\":0,\"original_line_count\":0,"
                        "\"threshold\":%" PRIu64 ",\"window\":%" PRIu64 "}\n",
                threshold, window);
        return 0;
    }
    uint64_t *hashes = calloc((size_t)N, sizeof(uint64_t));
    if (hashes == NULL) {
        fprintf(stderr, "fold: out of memory for hash table\n");
        return 1;
    }
    for (uint64_t i = 0; i < N; i++) {
        size_t off = indexed->index.offsets[i];
        LineView lv = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
        hashes[i] = line_signature_hash(lv);
    }

    uint64_t fold_count = 0;
    uint64_t skipped_lines = 0;
    uint64_t i = 0;
    while (i < N) {
        /* Can we even start a W-block here? Need W non-zero-sig lines starting at i. */
        bool block_ok = true;
        for (uint64_t k = 0; k < window; k++) {
            if (i + k >= N || hashes[i + k] == 0) { block_ok = false; break; }
        }
        if (!block_ok) {
            write_line_no_n(indexed, out, i + 1);
            i++;
            continue;
        }
        /* Count how many consecutive lines after i+window match the W-stride. */
        uint64_t j = i + window;
        while (j < N && hashes[j] != 0 && hashes[j] == hashes[j - window]) {
            j++;
        }
        uint64_t match = j - (i + window);  /* lines after the first block that mirror it */
        uint64_t reps = (match / window) + 1;  /* total block-copies in [i, i+window+match-1] (only count full reps) */
        uint64_t span_len = reps * window;     /* full lines covered by complete reps */
        uint64_t span_end = i + span_len;      /* exclusive */
        if (reps >= threshold) {
            /* Emit first W lines verbatim */
            for (uint64_t k = 0; k < window; k++) {
                write_line_no_n(indexed, out, i + k + 1);
            }
            fprintf(out,
                    "# ak_fold: block_reps=%" PRIu64 " window=%" PRIu64
                    " first_block=[%" PRIu64 "..%" PRIu64 "] last_block=[%" PRIu64 "..%" PRIu64
                    "] hidden_lines=%" PRIu64 "\n",
                    reps, window,
                    i + 1, i + window,
                    span_end - window + 1, span_end,
                    (reps - 2) * window);
            /* Emit last W lines verbatim (preserves final accumulator state) */
            for (uint64_t k = 0; k < window; k++) {
                write_line_no_n(indexed, out, span_end - window + k + 1);
            }
            fold_count++;
            skipped_lines += (reps - 2) * window;
            i = span_end;
        } else {
            /* No fold — write line i verbatim and advance one. */
            write_line_no_n(indexed, out, i + 1);
            i++;
        }
    }
    free(hashes);
    fprintf(stdout,
            "{\"type\":\"fold_summary\",\"folds_applied\":%" PRIu64
            ",\"lines_skipped\":%" PRIu64
            ",\"original_line_count\":%" PRIu64
            ",\"threshold\":%" PRIu64
            ",\"window\":%" PRIu64 "}\n",
            fold_count, skipped_lines, N, threshold, window);
    return 0;
}

static int run_fold(const IndexedFile *indexed, FILE *out, uint64_t threshold) {
    char prev_sig[512] = "";
    char cur_sig[512];
    uint64_t run_first = 0, run_last = 0;
    bool prev_has_sig = false;
    uint64_t fold_count = 0;
    uint64_t skipped_lines = 0;

    for (uint64_t line_no = 1; line_no <= indexed->index.count; line_no++) {
        size_t off = indexed->index.offsets[line_no - 1];
        LineView lv = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
        bool has_sig = extract_line_signature(lv, cur_sig, sizeof(cur_sig));

        if (!has_sig) {
            /* non-instruction line (call func / class / ret / blank) — flush any
             * pending run, then emit this line verbatim. Reset state.
             */
            fold_flush_run(indexed, out, run_first, run_last, prev_sig, threshold,
                           &fold_count, &skipped_lines);
            fwrite(lv.start, 1, lv.len, out);
            fputc('\n', out);
            run_first = 0;
            run_last = 0;
            prev_has_sig = false;
            prev_sig[0] = '\0';
            continue;
        }

        if (prev_has_sig && strcmp(cur_sig, prev_sig) == 0) {
            run_last = line_no;
        } else {
            fold_flush_run(indexed, out, run_first, run_last, prev_sig, threshold,
                           &fold_count, &skipped_lines);
            strncpy(prev_sig, cur_sig, sizeof(prev_sig) - 1);
            prev_sig[sizeof(prev_sig) - 1] = '\0';
            run_first = line_no;
            run_last = line_no;
            prev_has_sig = true;
        }
    }
    /* trailing run */
    fold_flush_run(indexed, out, run_first, run_last, prev_sig, threshold,
                   &fold_count, &skipped_lines);

    /* summary to stdout (not the output file) so callers can verify */
    fprintf(stdout, "{\"type\":\"fold_summary\",\"folds_applied\":%" PRIu64
                    ",\"lines_skipped\":%" PRIu64
                    ",\"original_line_count\":%" PRIu64
                    ",\"threshold\":%" PRIu64 "}\n",
            fold_count, skipped_lines, indexed->index.count, threshold);
    return 0;
}

static int cmd_lint(int argc, char **argv) {
    const char *path = NULL;
    uint64_t top_k = 10;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &top_k)) { fprintf(stderr, "invalid --top\n"); return 2; }
            if (top_k == 0) top_k = 10;
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL) { usage(stderr); return 2; }

    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_lint(&indexed, top_k);
    indexed_file_close(&indexed);
    return result;
}

static int cmd_fold(int argc, char **argv) {
    const char *in_path = NULL;
    const char *out_path = NULL;
    uint64_t threshold = 100;
    uint64_t window = 1;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--in") == 0 && i + 1 < argc) in_path = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out_path = argv[++i];
        else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &threshold) || threshold < 3) {
                fprintf(stderr, "invalid --threshold (must be >= 3)\n");
                return 2;
            }
        }
        else if (strcmp(argv[i], "--block") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &window) || window == 0 || window > 32) {
                fprintf(stderr, "invalid --block (must be in [1, 32])\n");
                return 2;
            }
        }
        else { usage(stderr); return 2; }
    }
    if (in_path == NULL || out_path == NULL) { usage(stderr); return 2; }

    IndexedFile indexed;
    if (indexed_file_open(in_path, &indexed) != 0) return 1;

    FILE *out = fopen(out_path, "w");
    if (out == NULL) {
        fprintf(stderr, "fopen failed: %s: %s\n", out_path, strerror(errno));
        indexed_file_close(&indexed);
        return 1;
    }

    int result = window > 1
        ? run_fold_block(&indexed, out, threshold, window)
        : run_fold(&indexed, out, threshold);
    fflush(out);
    fclose(out);
    indexed_file_close(&indexed);
    return result;
}

/* ===========================================================================
 * Sprint 3 extensions: callgraph / modgraph / hexblock
 * ===========================================================================
 */

/* Parse "call func: NAME(args)" line into name region. Returns (start, len)
 * pointing at NAME, or false if line doesn't match prefix.
 */
static bool parse_call_func_name(LineView line,
                                 const unsigned char **name_start, size_t *name_len) {
    static const unsigned char prefix[] = "call func: ";
    size_t plen = sizeof(prefix) - 1;
    if (line.len < plen) return false;
    if (memcmp(line.start, prefix, plen) != 0) return false;
    const unsigned char *p = line.start + plen;
    const unsigned char *end = line.start + line.len;
    /* Name continues until '(' or end of line. ObjC msgSend names contain '[]'
     * which we keep as part of the name.
     */
    const unsigned char *paren = NULL;
    for (const unsigned char *q = p; q < end; q++) {
        if (*q == '(') { paren = q; break; }
    }
    *name_start = p;
    *name_len = (paren != NULL ? (size_t)(paren - p) : (size_t)(end - p));
    /* Trim trailing whitespace */
    while (*name_len > 0 && (*name_start)[*name_len - 1] == ' ') (*name_len)--;
    return *name_len > 0;
}

static int run_callgraph_xref_to(const IndexedFile *indexed, const char *needle, uint64_t limit) {
    if (indexed->mapped.size == 0) return 0;
    size_t nlen = strlen(needle);
    if (nlen == 0) return 0;

    uint64_t emitted = 0;
    uint64_t total_hits = 0;
    for (uint64_t line_no = 1; line_no <= indexed->index.count; line_no++) {
        size_t off = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
        const unsigned char *name; size_t name_len;
        if (!parse_call_func_name(line, &name, &name_len)) continue;
        /* substring match (case-sensitive — call names are typically exact) */
        if (name_len < nlen) continue;
        bool hit = false;
        for (size_t i = 0; i + nlen <= name_len; i++) {
            if (memcmp(name + i, (const unsigned char *)needle, nlen) == 0) { hit = true; break; }
        }
        if (!hit) continue;
        total_hits++;
        if (emitted < limit) {
            fputs("{\"type\":\"callgraph_xref\",\"line\":", stdout);
            printf("%" PRIu64, line_no);
            fputs(",\"name\":", stdout);
            json_write_string(name, name_len);
            fputs(",\"instr\":", stdout);
            json_write_string(line.start, line.len);
            fputs("}\n", stdout);
            emitted++;
        }
    }
    fprintf(stdout, "{\"type\":\"callgraph_summary\",\"target\":");
    json_write_cstr(needle);
    printf(",\"total_hits\":%" PRIu64 ",\"emitted\":%" PRIu64 "}\n", total_hits, emitted);
    return 0;
}

static int run_callgraph_top(const IndexedFile *indexed, uint64_t top_k) {
    CountTable names; count_table_init(&names);
    uint64_t total_calls = 0;
    for (uint64_t line_no = 1; line_no <= indexed->index.count; line_no++) {
        size_t off = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
        const unsigned char *name; size_t name_len;
        if (!parse_call_func_name(line, &name, &name_len)) continue;
        count_table_bump(&names, name, name_len);
        total_calls++;
    }
    qsort(names.entries, names.count, sizeof(CountEntry), count_entry_cmp_desc);
    uint64_t emit_n = names.count < top_k ? names.count : top_k;
    fputs("{\"type\":\"callgraph_top\",\"total_calls\":", stdout);
    printf("%" PRIu64, total_calls);
    printf(",\"unique_names\":%zu", names.count);
    fputs(",\"top\":[", stdout);
    for (uint64_t i = 0; i < emit_n; i++) {
        if (i > 0) putchar(',');
        fputs("{\"name\":", stdout);
        json_write_cstr(names.entries[i].name);
        printf(",\"count\":%" PRIu64 "}", names.entries[i].count);
    }
    fputs("]}\n", stdout);
    count_table_free(&names);
    return 0;
}

static int cmd_callgraph(int argc, char **argv) {
    const char *path = NULL;
    const char *to_name = NULL;
    uint64_t top_k = 0;
    uint64_t limit = 100;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) to_name = argv[++i];
        else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &top_k)) { fprintf(stderr, "invalid --top\n"); return 2; }
        }
        else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &limit)) { fprintf(stderr, "invalid --limit\n"); return 2; }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL) { usage(stderr); return 2; }
    if (to_name == NULL && top_k == 0) {
        fprintf(stderr, "callgraph requires --to NAME or --top N\n"); return 2;
    }

    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = to_name != NULL
        ? run_callgraph_xref_to(&indexed, to_name, limit)
        : run_callgraph_top(&indexed, top_k);
    indexed_file_close(&indexed);
    return result;
}

/* modgraph: emit one row per (caller_module, callee_module, count). Detects
 * cross-module by scanning adjacent module-tagged lines and counting unique
 * directed transitions weighted by their occurrence. */
typedef struct {
    char from_name[96];
    char to_name[96];
    uint64_t count;
} EdgeEntry;

typedef struct {
    EdgeEntry *entries;
    size_t count;
    size_t capacity;
} EdgeTable;

static void edge_table_init(EdgeTable *t) { t->entries = NULL; t->count = 0; t->capacity = 0; }
static void edge_table_free(EdgeTable *t) { free(t->entries); t->entries = NULL; t->count = 0; t->capacity = 0; }

static int edge_table_bump(EdgeTable *t,
                           const unsigned char *from, size_t from_len,
                           const unsigned char *to, size_t to_len) {
    if (from_len >= sizeof(t->entries[0].from_name)) from_len = sizeof(t->entries[0].from_name) - 1;
    if (to_len >= sizeof(t->entries[0].to_name)) to_len = sizeof(t->entries[0].to_name) - 1;
    for (size_t i = 0; i < t->count; i++) {
        if (strlen(t->entries[i].from_name) == from_len &&
            strlen(t->entries[i].to_name) == to_len &&
            memcmp(t->entries[i].from_name, from, from_len) == 0 &&
            memcmp(t->entries[i].to_name, to, to_len) == 0) {
            t->entries[i].count++;
            return 0;
        }
    }
    if (t->count == t->capacity) {
        size_t nc = t->capacity == 0 ? 64 : t->capacity * 2;
        EdgeEntry *nx = realloc(t->entries, nc * sizeof(EdgeEntry));
        if (nx == NULL) return -1;
        t->entries = nx; t->capacity = nc;
    }
    memcpy(t->entries[t->count].from_name, from, from_len);
    t->entries[t->count].from_name[from_len] = '\0';
    memcpy(t->entries[t->count].to_name, to, to_len);
    t->entries[t->count].to_name[to_len] = '\0';
    t->entries[t->count].count = 1;
    t->count++;
    return 0;
}

static int edge_cmp_desc(const void *a, const void *b) {
    uint64_t ca = ((const EdgeEntry *)a)->count;
    uint64_t cb = ((const EdgeEntry *)b)->count;
    if (ca < cb) return 1;
    if (ca > cb) return -1;
    return 0;
}

static int run_modgraph(const IndexedFile *indexed, uint64_t top_k) {
    EdgeTable edges; edge_table_init(&edges);
    CountTable mods; count_table_init(&mods);
    char prev_mod[96] = "";
    size_t prev_mod_len = 0;
    bool have_prev = false;
    uint64_t total_transitions = 0;

    for (uint64_t line_no = 1; line_no <= indexed->index.count; line_no++) {
        size_t off = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
        const unsigned char *tag; size_t tag_len;
        if (!parse_module_tag(line, &tag, &tag_len)) continue;
        count_table_bump(&mods, tag, tag_len);
        if (have_prev) {
            if (tag_len != prev_mod_len || memcmp(tag, prev_mod, tag_len) != 0) {
                edge_table_bump(&edges, (const unsigned char *)prev_mod, prev_mod_len, tag, tag_len);
                total_transitions++;
            }
        }
        size_t copy_len = tag_len < sizeof(prev_mod) - 1 ? tag_len : sizeof(prev_mod) - 1;
        memcpy(prev_mod, tag, copy_len);
        prev_mod[copy_len] = '\0';
        prev_mod_len = copy_len;
        have_prev = true;
    }

    qsort(edges.entries, edges.count, sizeof(EdgeEntry), edge_cmp_desc);
    qsort(mods.entries, mods.count, sizeof(CountEntry), count_entry_cmp_desc);
    uint64_t emit_n = edges.count < top_k ? edges.count : top_k;

    fputs("{\"type\":\"modgraph\",\"total_transitions\":", stdout);
    printf("%" PRIu64, total_transitions);
    fputs(",\"modules\":[", stdout);
    for (size_t i = 0; i < mods.count; i++) {
        if (i > 0) putchar(',');
        fputs("{\"name\":", stdout);
        json_write_cstr(mods.entries[i].name);
        printf(",\"lines\":%" PRIu64 "}", mods.entries[i].count);
    }
    fputs("],\"top_edges\":[", stdout);
    for (uint64_t i = 0; i < emit_n; i++) {
        if (i > 0) putchar(',');
        fputs("{\"from\":", stdout);
        json_write_cstr(edges.entries[i].from_name);
        fputs(",\"to\":", stdout);
        json_write_cstr(edges.entries[i].to_name);
        printf(",\"count\":%" PRIu64 "}", edges.entries[i].count);
    }
    fputs("]}\n", stdout);
    edge_table_free(&edges);
    count_table_free(&mods);
    return 0;
}

static int cmd_modgraph(int argc, char **argv) {
    const char *path = NULL;
    uint64_t top_k = 30;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &top_k) || top_k == 0) { fprintf(stderr, "invalid --top\n"); return 2; }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL) { usage(stderr); return 2; }
    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_modgraph(&indexed, top_k);
    indexed_file_close(&indexed);
    return result;
}

/* hexblock: parse a "call func: NAME(args)" line at --line and return the
 * structured call block (optional hexdumps, optional class, ret).
 *
 * Block grammar:
 *   call func: NAME(arg1, arg2, ...)            ← REQUIRED, must be on --line
 *   [class : NAME]                              ← optional, ObjC msgSend
 *   [hexdump at address 0xA with length 0xL:    ← 0..N hexdump headers
 *     0xA+0: HH HH ... |ASCII|                  ← N data rows per header
 *     ...
 *   ]
 *   ret: 0xVAL                                  ← terminates the block
 *
 * Anything else terminates parsing without `ret` (incomplete block).
 */

static bool starts_with(LineView line, const char *prefix) {
    size_t plen = strlen(prefix);
    return line.len >= plen && memcmp(line.start, prefix, plen) == 0;
}

static bool parse_hex_header(LineView line, char *addr_buf, size_t addr_sz,
                             char *len_buf, size_t len_sz) {
    static const unsigned char p1[] = "hexdump at address ";
    static const unsigned char p2[] = " with length ";
    static const size_t p1len = sizeof(p1) - 1;
    static const size_t p2len = sizeof(p2) - 1;
    if (line.len < p1len + 4) return false;
    if (memcmp(line.start, p1, p1len) != 0) return false;
    const unsigned char *p = line.start + p1len;
    const unsigned char *end = line.start + line.len;
    const unsigned char *after = parse_hex_run(p, end, addr_buf, addr_sz);
    if (after == NULL) return false;
    if ((size_t)(end - after) < p2len) return false;
    if (memcmp(after, p2, p2len) != 0) return false;
    p = after + p2len;
    const unsigned char *after2 = parse_hex_run(p, end, len_buf, len_sz);
    if (after2 == NULL) return false;
    /* trailing ':' optional */
    return true;
}

/* Parse a "0xADDR: HH HH ... |ASCII|" hexdump body line; return true if
 * format matches. Writes raw hex_bytes and ascii_preview into out buffers. */
static bool parse_hex_body(LineView line, char *hex_out, size_t hex_sz,
                           char *ascii_out, size_t ascii_sz) {
    /* Look for "<addr>: " then bytes "HH " then "|...|" */
    const unsigned char *colon = NULL;
    const unsigned char *end = line.start + line.len;
    for (const unsigned char *p = line.start; p < end; p++) {
        if (*p == ':') { colon = p; break; }
    }
    if (colon == NULL || colon + 2 > end || colon[1] != ' ') return false;
    /* skip until '|' for ASCII region */
    const unsigned char *bar = NULL;
    for (const unsigned char *p = colon + 2; p < end; p++) {
        if (*p == '|') { bar = p; break; }
    }
    if (bar == NULL) return false;
    /* hex bytes are between colon+2 and bar; collapse spaces, take HH chars */
    size_t hi = 0;
    for (const unsigned char *p = colon + 2; p < bar && hi + 1 < hex_sz; p++) {
        if (*p == ' ') continue;
        hex_out[hi++] = (char)*p;
    }
    hex_out[hi] = '\0';
    /* ASCII region is between bar+1 and next '|' (or end) */
    const unsigned char *bar2 = NULL;
    for (const unsigned char *p = bar + 1; p < end; p++) {
        if (*p == '|') { bar2 = p; break; }
    }
    const unsigned char *ae = bar2 != NULL ? bar2 : end;
    size_t ai = 0;
    for (const unsigned char *p = bar + 1; p < ae && ai + 1 < ascii_sz; p++) {
        ascii_out[ai++] = (char)*p;
    }
    /* Trim trailing spaces (padding) */
    while (ai > 0 && ascii_out[ai - 1] == ' ') ai--;
    ascii_out[ai] = '\0';
    return true;
}

static int run_hexblock(const IndexedFile *indexed, uint64_t target_line, uint64_t max_lines) {
    if (target_line == 0 || target_line > indexed->index.count) {
        fprintf(stderr, "hexblock: --line out of range\n");
        return 1;
    }
    size_t off0 = indexed->index.offsets[target_line - 1];
    LineView call_line = line_at_offset(indexed->mapped.data, indexed->mapped.size, off0);
    const unsigned char *name; size_t name_len;
    if (!parse_call_func_name(call_line, &name, &name_len)) {
        fprintf(stderr, "hexblock: line %" PRIu64 " is not a 'call func:' line\n", target_line);
        return 1;
    }

    fputs("{\"type\":\"hexblock\",\"line\":", stdout);
    printf("%" PRIu64, target_line);
    fputs(",\"call\":", stdout);
    json_write_string(name, name_len);

    /* extract args: substring between first '(' and final ')' on call_line */
    const unsigned char *call_end = call_line.start + call_line.len;
    const unsigned char *lp = NULL;
    for (const unsigned char *p = call_line.start; p < call_end; p++) {
        if (*p == '(') { lp = p; break; }
    }
    if (lp != NULL) {
        const unsigned char *rp = NULL;
        for (const unsigned char *p = call_end - 1; p > lp; p--) {
            if (*p == ')') { rp = p; break; }
        }
        if (rp != NULL && rp > lp + 1) {
            fputs(",\"args_raw\":", stdout);
            json_write_string(lp + 1, (size_t)(rp - lp - 1));
        }
    }

    /* Parse subsequent lines: class? hexdump* ret? */
    bool first_dump_emitted = false;
    bool dumps_array_open = false;
    char addr_buf[64], len_buf[64];
    char hex_buf[2048], ascii_buf[256];
    char ret_buf[64] = "";
    char class_buf[128] = "";
    uint64_t scanned = 0;
    bool in_hexdump = false;

    for (uint64_t i = 1; i <= max_lines && target_line + i <= indexed->index.count; i++) {
        size_t off = indexed->index.offsets[target_line + i - 1];
        LineView lv = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
        scanned = i;

        if (lv.len == 0) break;

        /* class line: "class : NAME" or just "NAME" (we accept "class : ...") */
        if (class_buf[0] == '\0' && starts_with(lv, "class :")) {
            /* "class : NAME" */
            const unsigned char *p = lv.start + 7;
            const unsigned char *e = lv.start + lv.len;
            while (p < e && *p == ' ') p++;
            size_t take = (size_t)(e - p);
            if (take >= sizeof(class_buf)) take = sizeof(class_buf) - 1;
            memcpy(class_buf, p, take);
            class_buf[take] = '\0';
            continue;
        }

        /* ret terminator */
        if (starts_with(lv, "ret:")) {
            const unsigned char *p = lv.start + 4;
            const unsigned char *e = lv.start + lv.len;
            while (p < e && *p == ' ') p++;
            size_t take = (size_t)(e - p);
            if (take >= sizeof(ret_buf)) take = sizeof(ret_buf) - 1;
            memcpy(ret_buf, p, take);
            ret_buf[take] = '\0';
            break;
        }

        /* hexdump header */
        if (parse_hex_header(lv, addr_buf, sizeof(addr_buf), len_buf, sizeof(len_buf))) {
            if (!dumps_array_open) { fputs(",\"hexdumps\":[", stdout); dumps_array_open = true; }
            if (first_dump_emitted) putchar(',');
            first_dump_emitted = true;
            fputs("{\"address\":", stdout);
            json_write_cstr(addr_buf);
            fputs(",\"length\":", stdout);
            json_write_cstr(len_buf);
            fputs(",\"bytes_hex\":\"", stdout);
            hex_buf[0] = '\0';
            in_hexdump = true;
            continue;
        }

        if (in_hexdump && parse_hex_body(lv, hex_buf, sizeof(hex_buf), ascii_buf, sizeof(ascii_buf))) {
            /* Stream concatenated hex into the current "bytes_hex" field. */
            fputs(hex_buf, stdout);
            continue;
        }
        if (in_hexdump) {
            /* hexdump section ends: close bytes_hex, append ascii placeholder */
            fputs("\"}", stdout);
            in_hexdump = false;
        }

        /* Anything else: stop. */
        break;
    }

    if (in_hexdump) {
        fputs("\"}", stdout);
    }
    if (dumps_array_open) fputs("]", stdout);
    if (class_buf[0] != '\0') {
        fputs(",\"class\":", stdout);
        json_write_cstr(class_buf);
    }
    if (ret_buf[0] != '\0') {
        fputs(",\"ret\":", stdout);
        json_write_cstr(ret_buf);
    }
    printf(",\"lines_scanned\":%" PRIu64, scanned);
    fputs("}\n", stdout);
    return 0;
}

static int cmd_hexblock(int argc, char **argv) {
    const char *path = NULL;
    uint64_t line = 0;
    uint64_t max_lines = 1024;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--line") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &line) || line == 0) { fprintf(stderr, "invalid --line\n"); return 2; }
        }
        else if (strcmp(argv[i], "--max-lines") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &max_lines) || max_lines == 0) { fprintf(stderr, "invalid --max-lines\n"); return 2; }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL || line == 0) { usage(stderr); return 2; }
    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_hexblock(&indexed, line, max_lines);
    indexed_file_close(&indexed);
    return result;
}

/* ===========================================================================
 * Sprint 4 extensions: constscan / bytes
 * ===========================================================================
 */

typedef enum { FP_WEAK = 0, FP_MEDIUM = 1, FP_STRONG = 2 } Confidence;

static const char *confidence_str(Confidence c) {
    switch (c) {
        case FP_STRONG: return "strong";
        case FP_MEDIUM: return "medium";
        case FP_WEAK:   return "weak";
    }
    return "unknown";
}

typedef struct {
    const char *name;
    const char *category;    /* taxonomy: hash / cipher_sym / cipher_asym / ecc / crc / mac */
    Confidence  conf;
    const char *magic_hex;   /* "0x" + lowercase hex literal */
} Fingerprint;

/* Curated fingerprint constants.
 *
 * Each entry: {name, category, confidence, magic_hex}.
 *   category   — algorithm taxonomy (hash / cipher / ecc / crc).
 *   confidence — independent signal quality:
 *                  strong  : unique, RFC/standard-verified, real-trace 0 FP
 *                  medium  : algorithm-specific but somewhat short or shared
 *                            with adjacent primitives (e.g. SHA-256 init
 *                            word also appears in BLAKE2s IV).
 *                  weak    : known to overlap with general-purpose code
 *                            (hashmaps, golden-ratio derived constants).
 *
 * Constants in this table are byte-array S-box leading bytes for AES (the
 * raw 0x63,0x7c,0x77,0x7b sequence packed BE) and the T-table words for
 * Te0[0..3] (FIPS 197 mix-column derived). Both AES patterns are kept so
 * detection survives both byte-array and T-table implementations. AES-NI /
 * hardware-accelerated builds emit none of these — that is a known constscan
 * limitation, documented in tools/search/README.md.
 *
 * Values verified against original references:
 *   MD5/SHA-1/SHA-256 init  : RFC 6234 §5.3.{1,3,4}
 *   SHA-512 init            : RFC 6234 §5.3.5
 *   AES S-box / Te0         : FIPS 197 §5.1.1 + §5.2
 *   SHA-3 / Keccak RC       : FIPS 202 §3.2.5
 *   ChaCha20 sigma          : RFC 8439 §2.3
 *   SM3 IV                  : GM/T 0004-2012 §5.3
 *   SM4 FK / CK             : GM/T 0002-2012 §6.1, §6.2
 *   TEA delta               : Wheeler & Needham 1994, "TEA, a Tiny Encryption Algorithm"
 *   CRC32 polynomials       : IEEE 802.3 §3.2.8 (normal), zlib (reflected)
 *   FNV-1a 64-bit           : http://isthe.com/chongo/tech/comp/fnv/
 *   P-256                   : FIPS 186-4 §D.1.2.3
 */
static const Fingerprint FINGERPRINTS[] = {

    /* ---- Hash: MD5 init quartet ---- */
    {"MD5.A",                "hash",       FP_STRONG, "0x67452301"},
    {"MD5.B",                "hash",       FP_STRONG, "0xefcdab89"},
    {"MD5.C",                "hash",       FP_STRONG, "0x98badcfe"},
    {"MD5.D",                "hash",       FP_STRONG, "0x10325476"},

    /* ---- Hash: MD5 T table — RFC 1321 §3.4 step 4
     *      T[i] = floor( |sin(i)| * 2^32 )  for i ∈ [1, 64]
     *
     *      v0.9.2 addition (closes a major scan-strategy blind spot):
     *      The 4 IVs above appear ONCE per MD5 init. The T table is
     *      referenced 64 times per block compression — so on any real
     *      MD5 trace the T-table constants saturate hit counts while the
     *      IVs barely register. Adding the first 4 T-words is enough
     *      sentinel; full T[1..64] is in RFC 1321 Appendix A. */
    {"MD5.T[1]",             "hash",       FP_STRONG, "0xd76aa478"},
    {"MD5.T[2]",             "hash",       FP_STRONG, "0xe8c7b756"},
    {"MD5.T[3]",             "hash",       FP_STRONG, "0x242070db"},
    {"MD5.T[4]",             "hash",       FP_STRONG, "0xc1bdceee"},

    /* ---- Hash: SHA-1 ---- */
    {"SHA1.h4",              "hash",       FP_STRONG, "0xc3d2e1f0"},
    {"SHA1.K[0..19]",        "hash",       FP_STRONG, "0x5a827999"},
    {"SHA1.K[20..39]",       "hash",       FP_STRONG, "0x6ed9eba1"},
    {"SHA1.K[40..59]",       "hash",       FP_STRONG, "0x8f1bbcdc"},
    {"SHA1.K[60..79]",       "hash",       FP_STRONG, "0xca62c1d6"},

    /* ---- Hash: SHA-256 (32-bit init, BLAKE2s IV identical → medium) ---- */
    {"SHA256.h0",            "hash",       FP_MEDIUM, "0x6a09e667"},
    {"SHA256.h1",            "hash",       FP_MEDIUM, "0xbb67ae85"},
    {"SHA256.h2",            "hash",       FP_MEDIUM, "0x3c6ef372"},
    {"SHA256.h3",            "hash",       FP_MEDIUM, "0xa54ff53a"},
    {"SHA256.h4",            "hash",       FP_MEDIUM, "0x510e527f"},
    {"SHA256.h5",            "hash",       FP_MEDIUM, "0x9b05688c"},
    {"SHA256.h6",            "hash",       FP_MEDIUM, "0x1f83d9ab"},
    {"SHA256.h7",            "hash",       FP_MEDIUM, "0x5be0cd19"},

    /* ---- Hash: SHA-256 K table — FIPS 180-4 §4.2.2
     *      K[i] = first 32 bits of fractional parts of cube roots of
     *      first 64 primes.
     *
     *      v0.9.2 addition (same blind-spot fix as MD5.T): K is read 64
     *      times per block compression. Active SHA-256 traces will hit
     *      K-words far more frequently than IVs. We track K[0..7] as
     *      sentinel; full K[0..63] is in FIPS 180-4 Appendix A. */
    {"SHA256.K[0]",          "hash",       FP_STRONG, "0x428a2f98"},
    {"SHA256.K[1]",          "hash",       FP_STRONG, "0x71374491"},
    {"SHA256.K[2]",          "hash",       FP_STRONG, "0xb5c0fbcf"},
    {"SHA256.K[3]",          "hash",       FP_STRONG, "0xe9b5dba5"},
    {"SHA256.K[4]",          "hash",       FP_STRONG, "0x3956c25b"},
    {"SHA256.K[5]",          "hash",       FP_STRONG, "0x59f111f1"},
    {"SHA256.K[6]",          "hash",       FP_STRONG, "0x923f82a4"},
    {"SHA256.K[7]",          "hash",       FP_STRONG, "0xab1c5ed5"},

    /* ---- Hash: SHA-512 (BLAKE2b IV identical → medium, ambiguous algorithm) */
    {"SHA512.h0",            "hash",       FP_MEDIUM, "0x6a09e667f3bcc908"},
    {"SHA512.h1",            "hash",       FP_MEDIUM, "0xbb67ae8584caa73b"},
    {"SHA512.h2",            "hash",       FP_MEDIUM, "0x3c6ef372fe94f82b"},
    {"SHA512.h3",            "hash",       FP_MEDIUM, "0xa54ff53a5f1d36f1"},
    {"SHA512.h4",            "hash",       FP_MEDIUM, "0x510e527fade682d1"},
    {"SHA512.h5",            "hash",       FP_MEDIUM, "0x9b05688c2b3e6c1f"},
    {"SHA512.h6",            "hash",       FP_MEDIUM, "0x1f83d9abfb41bd6b"},
    {"SHA512.h7",            "hash",       FP_MEDIUM, "0x5be0cd19137e2179"},

    /* ---- Hash: SM3 IV (GM/T 0004-2012) ---- */
    {"SM3.IV0",              "hash",       FP_STRONG, "0x7380166f"},
    {"SM3.IV1",              "hash",       FP_STRONG, "0x4914b2b9"},
    {"SM3.IV2",              "hash",       FP_STRONG, "0x172442d7"},
    {"SM3.IV3",              "hash",       FP_STRONG, "0xda8a0600"},
    {"SM3.IV4",              "hash",       FP_STRONG, "0xa96f30bc"},
    {"SM3.IV5",              "hash",       FP_STRONG, "0x163138aa"},
    {"SM3.IV6",              "hash",       FP_STRONG, "0xe38dee4d"},
    {"SM3.IV7",              "hash",       FP_STRONG, "0xb0fb0e4e"},

    /* ---- Hash: SM3 round constants T_j (GM/T 0004-2012 §5.4)
     *      T_j = 0x79CC4519     for j ∈ [0, 15]
     *      T_j = 0x7A879D8A     for j ∈ [16, 63]
     *      These appear ~64 times per block (loop-body) vs IVs which
     *      appear once at init. v0.9.2 blind-spot fix. */
    {"SM3.T_j[0..15]",       "hash",       FP_STRONG, "0x79cc4519"},
    {"SM3.T_j[16..63]",      "hash",       FP_STRONG, "0x7a879d8a"},

    /* ---- Hash: SHA-3 / Keccak round constants (skip RC[0]=0x01, too generic) */
    {"SHA3.RC[1]",           "hash",       FP_STRONG, "0x0000000000008082"},
    {"SHA3.RC[2]",           "hash",       FP_STRONG, "0x800000000000808a"},
    {"SHA3.RC[4]",           "hash",       FP_STRONG, "0x000000000000808b"},

    /* ---- Hash: FNV-1a 64-bit (hashmaps / Go / Rust runtimes) ---- */
    {"FNV1a.prime64",        "hash",       FP_WEAK,   "0x100000001b3"},
    {"FNV1a.offset64",       "hash",       FP_WEAK,   "0xcbf29ce484222325"},

    /* ---- Cipher: AES — byte-array S-box (raw, NOT T-table) ---- */
    {"AES.sbox_bytes[0..3]", "cipher_sym", FP_MEDIUM, "0x637c777b"},
    {"AES.sbox_bytes[4..7]", "cipher_sym", FP_MEDIUM, "0xf26b6fc5"},
    {"AES.inv_sbox_bytes",   "cipher_sym", FP_MEDIUM, "0x52096ad5"},
    /* ---- Cipher: AES — T-table Te0[0..3] (mix-column expanded, FIPS 197) ---- */
    {"AES.Te0[0]",           "cipher_sym", FP_STRONG, "0xc66363a5"},
    {"AES.Te0[1]",           "cipher_sym", FP_STRONG, "0xf87c7c84"},
    {"AES.Te0[2]",           "cipher_sym", FP_STRONG, "0xee777799"},
    {"AES.Te0[3]",           "cipher_sym", FP_STRONG, "0xf67b7b8d"},

    /* ---- Cipher: SM4 (国密) ---- */
    {"SM4.sbox[0..3]",       "cipher_sym", FP_STRONG, "0xd690e9fe"},
    {"SM4.sbox[4..7]",       "cipher_sym", FP_STRONG, "0xcce13db7"},
    {"SM4.FK0",              "cipher_sym", FP_STRONG, "0xa3b1bac6"},
    {"SM4.FK1",              "cipher_sym", FP_STRONG, "0x56aa3350"},
    {"SM4.CK[0]",            "cipher_sym", FP_STRONG, "0x00070e15"},
    {"SM4.CK[1]",            "cipher_sym", FP_STRONG, "0x1c232a31"},
    {"SM4.CK[2]",            "cipher_sym", FP_STRONG, "0x383f464d"},
    {"SM4.CK[3]",            "cipher_sym", FP_STRONG, "0x545b6269"},

    /* ---- Cipher: ChaCha20 / Salsa20 sigma ---- */
    {"ChaCha20.sigma[0]",    "cipher_sym", FP_STRONG, "0x61707865"},
    {"ChaCha20.sigma[1]",    "cipher_sym", FP_STRONG, "0x3320646e"},
    {"ChaCha20.sigma[2]",    "cipher_sym", FP_STRONG, "0x79622d32"},
    {"ChaCha20.sigma[3]",    "cipher_sym", FP_STRONG, "0x6b206574"},

    /* ---- Cipher: TEA family (0x9e3779b9 also used by Knuth hash / xxHash) */
    {"TEA.delta",            "cipher_sym", FP_MEDIUM, "0x9e3779b9"},

    /* ---- Cipher hint: Whirlpool S-box first 4 bytes ---- */
    {"Whirlpool.S[0..3]",    "cipher_sym", FP_WEAK,   "0x18233481"},

    /* ---- Cipher: DES (FIPS 46-3) — implementation-specific tables
     *
     *      v0.9.2: imported from imj01y/trace-ui (28-magic table). DES
     *      has no built-in IV — the const0/const1/shifted0/shifted1
     *      values below come from a specific DES library's precomputed
     *      PC / SP-box tables and do NOT appear in the FIPS spec text
     *      directly. We add them as FP_WEAK pending verification on a
     *      real DES trace + corroboration with bl/blr to des_* /
     *      3des / triple_des call symbols.
     *
     *      DES.sbox_word[0..3] are the first 4 32-bit words of the
     *      combined SP-box (S-box + P-permutation, a common
     *      optimisation seen in libgcrypt / PolarSSL / mbedTLS DES). */
    {"DES.const0",           "cipher_sym", FP_WEAK,   "0xfee1a2b3"},
    {"DES.const1",           "cipher_sym", FP_WEAK,   "0xd7bef080"},
    {"DES.shifted0",         "cipher_sym", FP_WEAK,   "0x3a322a22"},
    {"DES.shifted1",         "cipher_sym", FP_WEAK,   "0x2a223a32"},
    {"DES.sbox_word[0]",     "cipher_sym", FP_MEDIUM, "0x2c1e241b"},
    {"DES.sbox_word[1]",     "cipher_sym", FP_MEDIUM, "0x5a7f361d"},
    {"DES.sbox_word[2]",     "cipher_sym", FP_MEDIUM, "0x3d4793c6"},
    {"DES.sbox_word[3]",     "cipher_sym", FP_MEDIUM, "0x0b0eedf8"},

    /* ---- MAC: Poly1305 r-mask clamp (RFC 8439 §2.5)
     *      r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
     *      Split into two 64-bit limbs (BE word order). */
    {"Poly1305.clamp_lo",    "mac",        FP_STRONG, "0x0ffffffc0fffffff"},
    {"Poly1305.clamp_hi",    "mac",        FP_STRONG, "0x0ffffffc0ffffffc"},

    /* ---- MAC: SipHash initial key constants — ASCII "somepseudorandomly..."
     *      sip-hash24 / sip-hash13 IV (HashDoS defense, used by Rust HashMap,
     *      Python str, libcrypto). */
    {"SipHash.k0",           "mac",        FP_STRONG, "0x736f6d6570736575"},
    {"SipHash.k1",           "mac",        FP_STRONG, "0x646f72616e646f6d"},

    /* ---- MAC: HMAC ipad / opad (RFC 2104 §2)
     *      ipad = 0x36 repeated 64×, opad = 0x5c repeated 64×.
     *      As 32-bit words: 0x36363636 / 0x5c5c5c5c. These appear in
     *      both the unmasked init and (after XOR) in the working buffer
     *      of any HMAC-* construction (HMAC-SHA1, HMAC-SHA256, etc).
     *      High-value signal for token-signing / API-auth flows. */
    {"HMAC.ipad",            "mac",        FP_STRONG, "0x36363636"},
    {"HMAC.opad",            "mac",        FP_STRONG, "0x5c5c5c5c"},

    /* ---- CRC: 32-bit polynomial constants ---- */
    {"CRC32.poly_reflected", "crc",        FP_STRONG, "0xedb88320"},
    {"CRC32.poly_normal",    "crc",        FP_STRONG, "0x04c11db7"},

    /* ---- ECC: NIST P-256 ---- */
    {"P256.order_low[0]",    "ecc",        FP_STRONG, "0xbce6faada7179e84"},
    {"P256.order_low[1]",    "ecc",        FP_STRONG, "0xf3b9cac2fc632551"},
    /* P-256 curve param b (FIPS 186-4 §D.1.2.3 — low 64-bit limb) */
    {"P256.b_lo",            "ecc",        FP_STRONG, "0xcc53b0f63bce3c3e"},

    /* ---- ECC: secp256k1 prime low 64-bit (Bitcoin / Ethereum) ---- */
    {"secp256k1.p_lo",       "ecc",        FP_STRONG, "0xfffffffefffffc2f"},

    /* ---- ECC: Ed25519 curve constant d low 64-bit
     *      d = -121665/121666 mod p, full d = 0x52036cee2b6ffe73...
     *      Distinguishes Ed25519 from X25519/Curve25519. */
    {"Ed25519.d_lo",         "ecc",        FP_STRONG, "0x52036cee2b6ffe73"},

    /* ---- ECC: Curve25519 ladder constant a24 = 121665 = (A-2)/4 where A=486662 */
    {"Curve25519.a24",       "ecc",        FP_MEDIUM, "0x1db41"},

    {NULL, NULL, FP_WEAK, NULL},
};

/* Evidence classification for a constscan hit line. The same magic may
 * appear in a line as: a movz/movk-built immediate (LOAD_IMM = real signal),
 * an ldr/ldp memory read producing the value (MEM_R = real signal, e.g. a
 * preloaded constant table), an ldr/ldp memory write address, or merely a
 * value computed by an ALU op (ALU = coincidental collision risk).
 *
 * Distinguishing these turns "37 hits of MD5.A" from a single integer into a
 * real-signal verdict.
 */
typedef enum {
    EV_LOAD_IMM,    /* mov/movz/movk + value as output */
    EV_MEM_R,       /* ldr/ldp/ldur with mem_r= + value as output */
    EV_MEM_R_ADDR,  /* magic appears as a memory address (mem_r=magic, mem_w=magic) */
    EV_MEM_W,       /* str/stp + mem_w with magic as output value */
    EV_ALU,         /* arithmetic op + value as output (collision risk) */
    EV_OTHER        /* magic appears in operands but not as output */
} EvidenceKind;

typedef struct {
    uint64_t load_imm;
    uint64_t mem_r;
    uint64_t mem_r_addr;
    uint64_t mem_w;
    uint64_t alu;
    uint64_t other;
} EvidenceCounts;

static bool mnem_is_mov_family(const unsigned char *m, size_t mlen) {
    if (mlen >= 3 && memcmp(m, "mov", 3) == 0) return true;  /* mov, movk, movz, movn */
    return false;
}

static bool mnem_is_load_family(const unsigned char *m, size_t mlen) {
    if (mlen >= 3 && memcmp(m, "ldr", 3) == 0) return true;
    if (mlen >= 3 && memcmp(m, "ldp", 3) == 0) return true;
    if (mlen >= 4 && memcmp(m, "ldur", 4) == 0) return true;
    return false;
}

/* Check whether the line ends with "-> [reg]=<magic>" (i.e. magic is the
 * instruction's output value, not just an operand). Scans the region after
 * the last "-> " up to end-of-line.
 */
static bool magic_is_output(LineView line, const char *magic, size_t mlen) {
    static const unsigned char arrow[] = " -> ";
    const unsigned char *a = mem_find(line.start, line.len, arrow, 4);
    if (a == NULL) return false;
    const unsigned char *region = a + 4;
    const unsigned char *end = line.start + line.len;
    /* Walk tokens "reg=value " */
    const unsigned char *p = region;
    while (p < end) {
        while (p < end && *p == ' ') p++;
        const unsigned char *eq = NULL;
        for (const unsigned char *q = p; q < end; q++) {
            if (*q == '=') { eq = q; break; }
            if (*q == ' ') break;
        }
        if (eq == NULL) { while (p < end && *p != ' ') p++; continue; }
        const unsigned char *vstart = eq + 1;
        if (vstart + mlen <= end &&
            memcmp(vstart, magic, mlen) == 0) {
            /* require value boundary: next char is space or end or punctuation */
            if (vstart + mlen == end ||
                vstart[mlen] == ' ' ||
                vstart[mlen] == ',' ||
                vstart[mlen] == ';') {
                return true;
            }
        }
        while (p < end && *p != ' ') p++;
    }
    return false;
}

static EvidenceKind classify_evidence(LineView line, const char *magic, size_t mlen) {
    /* mem_r=<magic> / mem_w=<magic> — magic appears as a memory ADDRESS */
    char mem_r_lit[80], mem_w_lit[80];
    int mr = snprintf(mem_r_lit, sizeof(mem_r_lit), "mem_r=%s", magic);
    int mw = snprintf(mem_w_lit, sizeof(mem_w_lit), "mem_w=%s", magic);
    if (mr > 0 && mem_find(line.start, line.len,
                          (const unsigned char *)mem_r_lit, (size_t)mr) != NULL) {
        return EV_MEM_R_ADDR;
    }
    if (mw > 0 && mem_find(line.start, line.len,
                          (const unsigned char *)mem_w_lit, (size_t)mw) != NULL) {
        return EV_MEM_W;
    }

    /* Determine instruction mnemonic */
    const unsigned char *mn = NULL, *op = NULL;
    size_t mn_len = 0, op_len = 0;
    bool has_mnem = parse_mnem_and_operands(line, &mn, &mn_len, &op, &op_len);
    (void)op; (void)op_len;

    bool is_output = magic_is_output(line, magic, mlen);

    if (has_mnem && is_output) {
        if (mnem_is_mov_family(mn, mn_len)) return EV_LOAD_IMM;
        if (mnem_is_load_family(mn, mn_len)) {
            /* If line also has mem_r= without matching the magic, it's table load */
            if (mem_find(line.start, line.len, (const unsigned char *)"mem_r=", 6) != NULL) {
                return EV_MEM_R;
            }
            return EV_MEM_R;  /* register-to-register style ldr without explicit mem_r still treated as load */
        }
        return EV_ALU;
    }
    return EV_OTHER;
}

static const char *evidence_verdict(const EvidenceCounts *e) {
    if (e->load_imm > 0 || e->mem_r > 0) return "real";
    if (e->mem_w > 0 || e->mem_r_addr > 0) return "weak";
    if (e->alu > 0) return "alu_only";
    return "other";
}

static int run_constscan(const IndexedFile *indexed, uint64_t limit_per_fp) {
    size_t fp_count = 0;
    while (FINGERPRINTS[fp_count].name != NULL) fp_count++;

    fputs("{\"type\":\"constscan\",\"hits\":[", stdout);
    bool emitted_any = false;

    for (size_t f = 0; f < fp_count; f++) {
        const Fingerprint *fp = &FINGERPRINTS[f];
        BmhSearcher s;
        if (bmh_init(&s, fp->magic_hex) != 0) return 1;
        size_t mlen = strlen(fp->magic_hex);

        uint64_t total_hits = 0;
        EvidenceCounts ev = {0};
        uint64_t sample_lines[16];
        size_t sample_n = 0;

        for (uint64_t line_no = 1; line_no <= indexed->index.count; line_no++) {
            size_t off = indexed->index.offsets[line_no - 1];
            LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
            const unsigned char *hit = bmh_find(&s, line.start, line.len);
            if (hit == NULL) continue;
            /* boundary check — not a prefix of a longer hex run */
            const unsigned char *after = hit + mlen;
            if (after < line.start + line.len) {
                unsigned char c = *after;
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F')) {
                    continue;
                }
            }
            total_hits++;
            EvidenceKind k = classify_evidence(line, fp->magic_hex, mlen);
            switch (k) {
                case EV_LOAD_IMM:    ev.load_imm++;    break;
                case EV_MEM_R:       ev.mem_r++;       break;
                case EV_MEM_R_ADDR:  ev.mem_r_addr++;  break;
                case EV_MEM_W:       ev.mem_w++;       break;
                case EV_ALU:         ev.alu++;         break;
                case EV_OTHER:       ev.other++;       break;
            }
            if (sample_n < limit_per_fp && sample_n < (sizeof(sample_lines)/sizeof(sample_lines[0]))) {
                sample_lines[sample_n++] = line_no;
            }
        }

        bmh_destroy(&s);
        if (total_hits == 0) continue;

        if (emitted_any) putchar(',');
        emitted_any = true;
        fputs("{\"fingerprint\":", stdout);
        json_write_cstr(fp->name);
        fputs(",\"category\":", stdout);
        json_write_cstr(fp->category);
        fputs(",\"confidence\":", stdout);
        json_write_cstr(confidence_str(fp->conf));
        fputs(",\"magic\":", stdout);
        json_write_cstr(fp->magic_hex);
        printf(",\"total_hits\":%" PRIu64, total_hits);
        printf(",\"evidence\":{\"load_imm\":%" PRIu64
               ",\"mem_r\":%" PRIu64
               ",\"mem_r_addr\":%" PRIu64
               ",\"mem_w\":%" PRIu64
               ",\"alu\":%" PRIu64
               ",\"other\":%" PRIu64 "}",
               ev.load_imm, ev.mem_r, ev.mem_r_addr, ev.mem_w, ev.alu, ev.other);
        fputs(",\"verdict\":", stdout);
        json_write_cstr(evidence_verdict(&ev));
        fputs(",\"sample_lines\":[", stdout);
        for (size_t i = 0; i < sample_n; i++) {
            if (i > 0) putchar(',');
            printf("%" PRIu64, sample_lines[i]);
        }
        fputs("]}", stdout);
    }
    fputs("]}\n", stdout);
    return 0;
}

static int cmd_constscan(int argc, char **argv) {
    const char *path = NULL;
    uint64_t limit_per_fp = 5;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &limit_per_fp) || limit_per_fp == 0) {
                fprintf(stderr, "invalid --samples\n"); return 2;
            }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL) { usage(stderr); return 2; }
    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_constscan(&indexed, limit_per_fp);
    indexed_file_close(&indexed);
    return result;
}

/* bytes: search for a hex literal across the trace, automatically also trying
 * byte-reversed and leading-zero-stripped variants. Emits ALL hit line numbers
 * (no token-bloat from full line text — use trace_context if you need it).
 *
 * Use this when trace_search's 100-limit isn't enough or you want the full
 * occurrence set for a specific value.
 */
static int run_bytes_scan(const IndexedFile *indexed, const char *raw_hex,
                          uint64_t limit, bool emit_context_text) {
    /* canonicalize: ensure 0x prefix, lowercase */
    char canonical[80];
    size_t in_len = strlen(raw_hex);
    if (in_len < 3 || (raw_hex[0] != '0' || (raw_hex[1] != 'x' && raw_hex[1] != 'X'))) {
        fprintf(stderr, "bytes: query must be 0x-prefixed hex\n");
        return 2;
    }
    if (in_len + 1 > sizeof(canonical)) {
        fprintf(stderr, "bytes: hex too long\n");
        return 2;
    }
    canonical[0] = '0'; canonical[1] = 'x';
    for (size_t i = 2; i < in_len; i++) {
        char c = raw_hex[i];
        if (c >= 'A' && c <= 'F') c = (char)(c + ('a' - 'A'));
        canonical[i] = c;
    }
    canonical[in_len] = '\0';

    /* Build variants: canonical, byte-reversed (even-length), leading-zero stripped */
    char variants[3][80];
    int variant_count = 0;
    strncpy(variants[variant_count++], canonical, sizeof(variants[0]) - 1);

    /* byte-reversed */
    size_t hex_len = in_len - 2;
    if (hex_len % 2 == 0 && hex_len > 2) {
        char *rev = variants[variant_count];
        rev[0] = '0'; rev[1] = 'x';
        for (size_t i = 0; i < hex_len; i += 2) {
            size_t src = 2 + hex_len - i - 2;
            rev[2 + i] = canonical[src];
            rev[2 + i + 1] = canonical[src + 1];
        }
        rev[2 + hex_len] = '\0';
        if (strcmp(rev, canonical) != 0) variant_count++;
    }
    /* leading-zero stripped */
    if (hex_len > 1) {
        const char *p = canonical + 2;
        while (*p == '0' && *(p + 1) != '\0') p++;
        if (p > canonical + 2) {
            char *trim = variants[variant_count];
            trim[0] = '0'; trim[1] = 'x';
            size_t plen = strlen(p);
            if (plen + 3 <= sizeof(variants[0])) {
                memcpy(trim + 2, p, plen);
                trim[2 + plen] = '\0';
                if (strcmp(trim, canonical) != 0) variant_count++;
            }
        }
    }

    fputs("{\"type\":\"bytes_summary\",\"queries\":[", stdout);
    for (int v = 0; v < variant_count; v++) {
        if (v > 0) putchar(',');
        json_write_cstr(variants[v]);
    }
    fputs("],\"hits\":[", stdout);

    uint64_t total_emitted = 0;
    bool any = false;
    for (int v = 0; v < variant_count && total_emitted < limit; v++) {
        BmhSearcher s;
        if (bmh_init(&s, variants[v]) != 0) return 1;
        size_t mlen = strlen(variants[v]);
        for (uint64_t line_no = 1;
             line_no <= indexed->index.count && total_emitted < limit;
             line_no++) {
            size_t off = indexed->index.offsets[line_no - 1];
            LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
            const unsigned char *hit = bmh_find(&s, line.start, line.len);
            if (hit == NULL) continue;
            /* boundary: not a prefix of a longer hex run */
            const unsigned char *after = hit + mlen;
            if (after < line.start + line.len) {
                unsigned char c = *after;
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F')) continue;
            }
            if (any) putchar(',');
            any = true;
            fputs("{\"line\":", stdout);
            printf("%" PRIu64, line_no);
            fputs(",\"variant\":", stdout);
            json_write_cstr(variants[v]);
            if (emit_context_text) {
                fputs(",\"instr\":", stdout);
                json_write_string(line.start, line.len);
            }
            putchar('}');
            total_emitted++;
        }
        bmh_destroy(&s);
    }
    fputs("]}\n", stdout);
    return 0;
}

static int cmd_bytes(int argc, char **argv) {
    const char *path = NULL;
    const char *query = NULL;
    uint64_t limit = 100;
    bool emit_text = false;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--query") == 0 && i + 1 < argc) query = argv[++i];
        else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &limit) || limit == 0) { fprintf(stderr, "invalid --limit\n"); return 2; }
        }
        else if (strcmp(argv[i], "--with-text") == 0) emit_text = true;
        else { usage(stderr); return 2; }
    }
    if (path == NULL || query == NULL) { usage(stderr); return 2; }
    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_bytes_scan(&indexed, query, limit, emit_text);
    indexed_file_close(&indexed);
    return result;
}

/* ===========================================================================
 * Sprint 6 extensions: cryptoinstr — ARM Crypto Extensions instruction scanner
 *
 * Detects hardware-accelerated cryptographic primitives that constscan
 * is structurally blind to. When a binary uses ARMv8 Crypto Extensions
 * (AES-NI equivalent on ARM, available since ARMv8.0 / iPhone 5s+), the
 * software S-box / round-constant tables are NOT loaded — the magic numbers
 * never appear in the trace. The only signal is the mnemonic itself.
 *
 * Real-world coverage:
 *   ARMv8.0  AES (aese/aesmc/aesd/aesimc), SHA-1, SHA-256
 *   ARMv8.2  SHA-512, SM3, SM4, GHASH (pmull double-length)
 *   ARMv8.4  SHA-3 (eor3/rax1/xar/bcax)
 *   ARMv8.5+ no new crypto opcodes
 *
 * Used by: iOS CryptoKit, BoringSSL ARM backend, Android Keystore HW path,
 * libsodium-arm, mbedtls ARMv8 build, and most modern OEM crypto SDKs.
 * If a trace shows aese but constscan shows zero AES.sbox hits, that is
 * AES-NI in action — NOT a missing implementation.
 *
 * Mnemonic → primitive references:
 *   ARM ARM (DDI 0487) §C7.2 Crypto and SHA instructions
 *   FIPS 197 (AES)  + FIPS 180-4 (SHA-1/256/512) + FIPS 202 (SHA-3)
 *   GM/T 0002-2012 (SM4)  + GM/T 0004-2012 (SM3)
 * ===========================================================================
 */

typedef struct {
    const char *mnem;
    const char *primitive;   /* AES / SHA-1 / SHA-256 / SHA-512 / SHA-3 / GHASH / SM3 / SM4 */
    Confidence  conf;
    const char *note;
} CryptoInsn;

static const CryptoInsn CRYPTO_INSNS[] = {
    /* AES (ARMv8.0) */
    {"aese",      "AES",     FP_STRONG, "SubBytes + ShiftRows + AddRoundKey"},
    {"aesmc",     "AES",     FP_STRONG, "MixColumns"},
    {"aesd",      "AES",     FP_STRONG, "InvSubBytes + InvShiftRows + AddRoundKey"},
    {"aesimc",    "AES",     FP_STRONG, "InvMixColumns"},

    /* SHA-1 (ARMv8.0) */
    {"sha1c",     "SHA-1",   FP_STRONG, "hash update (Ch round)"},
    {"sha1m",     "SHA-1",   FP_STRONG, "hash update (Maj round)"},
    {"sha1p",     "SHA-1",   FP_STRONG, "hash update (Parity round)"},
    {"sha1h",     "SHA-1",   FP_STRONG, "fixed rotate"},
    {"sha1su0",   "SHA-1",   FP_STRONG, "schedule update 0"},
    {"sha1su1",   "SHA-1",   FP_STRONG, "schedule update 1"},

    /* SHA-256 (ARMv8.0) */
    {"sha256h",   "SHA-256", FP_STRONG, "hash update part 1"},
    {"sha256h2",  "SHA-256", FP_STRONG, "hash update part 2"},
    {"sha256su0", "SHA-256", FP_STRONG, "schedule update 0"},
    {"sha256su1", "SHA-256", FP_STRONG, "schedule update 1"},

    /* SHA-512 (ARMv8.2) */
    {"sha512h",   "SHA-512", FP_STRONG, "hash update part 1"},
    {"sha512h2",  "SHA-512", FP_STRONG, "hash update part 2"},
    {"sha512su0", "SHA-512", FP_STRONG, "schedule update 0"},
    {"sha512su1", "SHA-512", FP_STRONG, "schedule update 1"},

    /* SHA-3 / Keccak (ARMv8.2) — eor3 is widely used outside SHA-3 so medium */
    {"eor3",      "SHA-3",   FP_MEDIUM, "triple-XOR (Keccak χ step; also general 3-way XOR)"},
    {"rax1",      "SHA-3",   FP_STRONG, "rotate-add-XOR (Keccak ρ+π)"},
    {"xar",       "SHA-3",   FP_STRONG, "XOR-and-rotate (Keccak θ)"},
    {"bcax",      "SHA-3",   FP_STRONG, "bit-clear-AND-XOR (Keccak χ)"},

    /* GHASH / GCM (ARMv8.0 pmull, ARMv8.4 pmull2 for 64x64→128 fully) — medium
     * because pmull also encodes generic GF(2^n) multiply for non-GHASH uses. */
    {"pmull",     "GHASH",   FP_MEDIUM, "polynomial multiply low (GHASH/GMAC; also generic GF(2^n) mul)"},
    {"pmull2",    "GHASH",   FP_MEDIUM, "polynomial multiply high"},

    /* SM3 (ARMv8.2) */
    {"sm3partw1", "SM3",     FP_STRONG, "schedule update part 1"},
    {"sm3partw2", "SM3",     FP_STRONG, "schedule update part 2"},
    {"sm3ss1",    "SM3",     FP_STRONG, "sigma_1"},
    {"sm3tt1a",   "SM3",     FP_STRONG, "hash update T1 part A"},
    {"sm3tt1b",   "SM3",     FP_STRONG, "hash update T1 part B"},
    {"sm3tt2a",   "SM3",     FP_STRONG, "hash update T2 part A"},
    {"sm3tt2b",   "SM3",     FP_STRONG, "hash update T2 part B"},

    /* SM4 (ARMv8.2) */
    {"sm4e",      "SM4",     FP_STRONG, "encryption round"},
    {"sm4ekey",   "SM4",     FP_STRONG, "key expansion"},

    {NULL, NULL, FP_WEAK, NULL},
};

static int run_cryptoinstr(const IndexedFile *indexed, uint64_t limit_per_insn) {
    size_t insn_count = 0;
    while (CRYPTO_INSNS[insn_count].mnem != NULL) insn_count++;

    /* Per-insn counters + sample lines */
    uint64_t *hits = calloc(insn_count, sizeof(uint64_t));
    uint64_t (*samples)[8] = calloc(insn_count, sizeof(*samples));
    uint64_t *sample_n = calloc(insn_count, sizeof(uint64_t));
    if (!hits || !samples || !sample_n) {
        free(hits); free(samples); free(sample_n);
        fprintf(stderr, "cryptoinstr: out of memory\n");
        return 1;
    }
    if (limit_per_insn > 8) limit_per_insn = 8;

    /* Single pass over the trace */
    for (uint64_t line_no = 1; line_no <= indexed->index.count; line_no++) {
        size_t off = indexed->index.offsets[line_no - 1];
        LineView line = line_at_offset(indexed->mapped.data, indexed->mapped.size, off);
        const unsigned char *mn, *op;
        size_t mn_len, op_len;
        if (!parse_mnem_and_operands(line, &mn, &mn_len, &op, &op_len)) continue;
        (void)op; (void)op_len;
        /* Exact mnemonic match (case-sensitive — GumTrace emits lowercase). */
        for (size_t i = 0; i < insn_count; i++) {
            size_t l = strlen(CRYPTO_INSNS[i].mnem);
            if (mn_len == l && memcmp(mn, CRYPTO_INSNS[i].mnem, l) == 0) {
                hits[i]++;
                if (sample_n[i] < limit_per_insn) {
                    samples[i][sample_n[i]++] = line_no;
                }
                break;
            }
        }
    }

    /* Aggregate per-primitive verdict */
    fputs("{\"type\":\"cryptoinstr\",\"hits\":[", stdout);
    bool emitted = false;
    for (size_t i = 0; i < insn_count; i++) {
        if (hits[i] == 0) continue;
        if (emitted) putchar(',');
        emitted = true;
        fputs("{\"mnem\":", stdout);
        json_write_cstr(CRYPTO_INSNS[i].mnem);
        fputs(",\"primitive\":", stdout);
        json_write_cstr(CRYPTO_INSNS[i].primitive);
        fputs(",\"confidence\":", stdout);
        json_write_cstr(confidence_str(CRYPTO_INSNS[i].conf));
        fputs(",\"note\":", stdout);
        json_write_cstr(CRYPTO_INSNS[i].note);
        printf(",\"total_hits\":%" PRIu64, hits[i]);
        fputs(",\"sample_lines\":[", stdout);
        for (uint64_t k = 0; k < sample_n[i]; k++) {
            if (k > 0) putchar(',');
            printf("%" PRIu64, samples[i][k]);
        }
        fputs("]}", stdout);
    }
    fputs("],\"primitives_present\":[", stdout);
    /* dedupe primitive names */
    bool first_prim = true;
    for (size_t i = 0; i < insn_count; i++) {
        if (hits[i] == 0) continue;
        bool dup = false;
        for (size_t j = 0; j < i; j++) {
            if (hits[j] > 0 && strcmp(CRYPTO_INSNS[j].primitive, CRYPTO_INSNS[i].primitive) == 0) {
                dup = true; break;
            }
        }
        if (dup) continue;
        if (!first_prim) putchar(',');
        first_prim = false;
        json_write_cstr(CRYPTO_INSNS[i].primitive);
    }
    fputs("]}\n", stdout);

    free(hits); free(samples); free(sample_n);
    return 0;
}

static int cmd_cryptoinstr(int argc, char **argv) {
    const char *path = NULL;
    uint64_t samples = 5;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &samples) || samples == 0) {
                fprintf(stderr, "invalid --samples\n"); return 2;
            }
        }
        else { usage(stderr); return 2; }
    }
    if (path == NULL) { usage(stderr); return 2; }
    IndexedFile indexed;
    if (indexed_file_open(path, &indexed) != 0) return 1;
    int result = run_cryptoinstr(&indexed, samples);
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
    if (strcmp(argv[1], "lint") == 0) {
        return cmd_lint(argc, argv);
    }
    if (strcmp(argv[1], "fold") == 0) {
        return cmd_fold(argc, argv);
    }
    if (strcmp(argv[1], "callgraph") == 0) {
        return cmd_callgraph(argc, argv);
    }
    if (strcmp(argv[1], "modgraph") == 0) {
        return cmd_modgraph(argc, argv);
    }
    if (strcmp(argv[1], "hexblock") == 0) {
        return cmd_hexblock(argc, argv);
    }
    if (strcmp(argv[1], "constscan") == 0) {
        return cmd_constscan(argc, argv);
    }
    if (strcmp(argv[1], "bytes") == 0) {
        return cmd_bytes(argc, argv);
    }
    if (strcmp(argv[1], "cryptoinstr") == 0) {
        return cmd_cryptoinstr(argc, argv);
    }
    usage(stderr);
    return 2;
}
