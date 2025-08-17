#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "template.h"
#include "sqlite3utils.h"

#define TRACE(...) {}
//#define TRACE(fmt, ...) printf((fmt "\n"), ## __VA_ARGS__);

typedef struct CachedProgram CachedProgram;
struct CachedProgram {
    char           path[1<<8];
    int            pathlen;
    WL_Program     program;
};

struct TemplateCache {
    int count;
    int capacity_log2;
    CachedProgram pool[];
};

TemplateCache *template_cache_init(int capacity_log2)
{
    TemplateCache *cache = malloc(sizeof(TemplateCache) + (1 << capacity_log2) * sizeof(CachedProgram));
    if (cache == NULL)
        return NULL;

    cache->count = 0;
    cache->capacity_log2 = capacity_log2;

    for (int i = 0; i < (1 << capacity_log2); i++)
        cache->pool[i].pathlen = -1;
    return cache;
}

void template_cache_free(TemplateCache *cache)
{
    free(cache);
}

static unsigned long djb2(WL_String str)
{
    char *ptr = str.ptr;
    char *end = str.ptr + str.len;

    unsigned long hash = 5381;
    int c;
    while (ptr < end && (c = *ptr++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

static int lookup(TemplateCache *cache, WL_String path)
{
    int mask = (1 << cache->capacity_log2) - 1;
    int hash = djb2(path);
    int i = hash & mask;
    int perturb = hash;
    for (;;) {

        if (cache->pool[i].pathlen == -1)
            return i;

        if (wl_streq(path, cache->pool[i].path, cache->pool[i].pathlen))
            return i;

        perturb >>= 5;
        i = (i * 5 + 1 + perturb) & mask;
    }

    return -1;
}

typedef struct LoadedFile LoadedFile;
struct LoadedFile {
    LoadedFile* next;
    int         len;
    char        data[];
};

static LoadedFile *load_file(WL_String path)
{
    char buf[1<<10];
    if (path.len >= (int) sizeof(buf))
        return NULL;
    memcpy(buf, path.ptr, path.len);
    buf[path.len] = '\0';

    FILE *stream = fopen(buf, "rb");
    if (stream == NULL)
        return NULL;

    int ret = fseek(stream, 0, SEEK_END);
    if (ret) {
        fclose(stream);
        return NULL;
    }

    long tmp = ftell(stream);
    if (tmp < 0 || tmp > INT_MAX) {
        fclose(stream);
        return NULL;
    }
    int len = (int) tmp;

    ret = fseek(stream, 0, SEEK_SET);
    if (ret) {
        fclose(stream);
        return NULL;
    }

    LoadedFile *result = malloc(sizeof(LoadedFile) + len + 1);
    if (result == NULL) {
        fclose(stream);
        return NULL;
    }
    result->next = NULL;
    result->len  = len;

    int read_len = fread(result->data, 1, len+1, stream);
    if (read_len != len || ferror(stream) || !feof(stream)) {
        fclose(stream);
        free(result);
        return NULL;
    }

    fclose(stream);
    return result;
}

static void free_loaded_files(LoadedFile *loaded_file)
{
    while (loaded_file) {
        LoadedFile *next = loaded_file->next;
        free(loaded_file);
        loaded_file = next;
    }
}

static int compile(WL_String path, WL_Program *program, WL_Arena *arena)
{
    WL_Compiler *compiler = wl_compiler_init(arena);
    if (compiler == NULL) {
        TRACE("Couldn't initialize WL compiler object");
        return -1;
    }

    LoadedFile *loaded_file_head = NULL;
    LoadedFile **loaded_file_tail = &loaded_file_head;

    for (int i = 0;; i++) {

        LoadedFile *loaded_file = load_file(path);
        if (loaded_file == NULL) {
            TRACE("Couldn't load file '%.*s'", path.len, path.ptr);
            free_loaded_files(loaded_file_head);
            return -1;
        }

        *loaded_file_tail = loaded_file;
        loaded_file_tail = &loaded_file->next;

        WL_String content = { loaded_file->data, loaded_file->len };
        WL_AddResult result = wl_compiler_add(compiler, content);

        if (result.type == WL_ADD_ERROR) {
            TRACE("Compilation failed (%s)", wl_compiler_error(compiler).ptr);
            free_loaded_files(loaded_file_head);
            return -1;
        }

        if (result.type == WL_ADD_LINK) break;

        assert(result.type == WL_ADD_AGAIN);
        path = result.path;
    }

    int ret = wl_compiler_link(compiler, program);
    if (ret < 0) {
        TRACE("Compilation failed (%s)", wl_compiler_error(compiler).ptr);
        return -1;
    }

    free_loaded_files(loaded_file_head);

    TRACE("Compilation succeded");
    return 0;
}

static int query_routine(WL_Runtime *rt, SQLiteCache *dbcache)
{
    int num_args = wl_arg_count(rt);
    if (num_args == 0)
        return 0;

    WL_String format;
    if (!wl_arg_str(rt, 0, &format))
        return -1;

    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare(dbcache, &stmt, format.ptr, format.len);
    if (ret != SQLITE_OK)
        return -1;

    for (int i = 1; i < num_args; i++) {

        int64_t ival;
        double  fval;
        WL_String str;

        if (wl_arg_none(rt, i))
            ret = sqlite3_bind_null  (stmt, i);
        else if (wl_arg_s64(rt, i, &ival))
            ret = sqlite3_bind_int64 (stmt, i, ival);
        else if (wl_arg_f64(rt, i, &fval))
            ret = sqlite3_bind_double(stmt, i, fval);
        else if (wl_arg_str(rt, i, &str))
            ret = sqlite3_bind_text  (stmt, i, str.ptr, str.len, NULL);
        else assert(0);

        if (ret != SQLITE_OK) {
            sqlite3_reset(stmt);
            return -1;
        }
    }

    wl_push_array(rt, 0);

    while (sqlite3_step(stmt) == SQLITE_ROW) {

        int num_cols = sqlite3_column_count(stmt);
        if (num_cols < 0) {
            sqlite3_reset(stmt);
            return -1;
        }

        wl_push_map(rt, num_cols);

        for (int i = 0; i < num_cols; i++) {
            ret = sqlite3_column_type(stmt, i);
            switch (ret) {

                case SQLITE_INTEGER:
                {
                    int64_t x = sqlite3_column_int64(stmt, i);
                    wl_push_s64(rt, x);
                }
                break;

                case SQLITE_FLOAT:
                {
                    double x = sqlite3_column_double(stmt, i);
                    wl_push_f64(rt, x);
                }
                break;

                case SQLITE_TEXT:
                {
                    const void *x = sqlite3_column_text(stmt, i);
                    int n = sqlite3_column_bytes(stmt, i);
                    wl_push_str(rt, (WL_String) { (char*) x, n });
                }
                break;

                case SQLITE_BLOB:
                {
                    const void *x = sqlite3_column_blob(stmt, i);
                    int n = sqlite3_column_bytes(stmt, i);
                    wl_push_str(rt, (WL_String) { (char*) x, n });
                }
                break;

                case SQLITE_NULL:
                {
                    wl_push_none(rt);
                }
                break;
            }

            const char *name = sqlite3_column_name(stmt, i);

            wl_push_str(rt, (WL_String) { (char*) name, strlen(name) });
            wl_insert(rt);
        }

        wl_append(rt);
    }

    sqlite3_reset(stmt);
    return 0;
}

static void push_sysvar(WL_Runtime *rt, WL_String name, SQLiteCache *dbcache, int user_id, int post_id)
{
    (void) dbcache;

    if (wl_streq(name, "login_user_id", -1)) {

        if (user_id < 0)
            wl_push_none(rt);
        else
            wl_push_s64(rt, user_id);

    } else if (wl_streq(name, "post_id", -1)) {

        if (post_id < 0)
            wl_push_none(rt);
        else
            wl_push_s64(rt, post_id);
    }
}

static void push_syscall(WL_Runtime *rt, WL_String name, SQLiteCache *dbcache)
{
    if (wl_streq(name, "query", -1)) {
        query_routine(rt, dbcache);
        return;
    }
}

static int get_or_create_program(TemplateCache *cache, WL_String path, WL_Arena *arena, WL_Program *program)
{
    if (cache == NULL)
        return -1;

    int i = lookup(cache, path);
    if (cache->pool[i].pathlen == -1) {

        WL_Program program;
        int ret = compile(path, &program, arena);
        if (ret < 0) return -1;

        void *p = malloc(program.len);
        if (p == NULL)
            return -1;
        memcpy(p, program.ptr, program.len);
        program.ptr = p;

        if ((int) sizeof(cache->pool->path) <= path.len)
            return -1;
        memcpy(cache->pool[i].path, path.ptr, path.len);
        cache->pool[i].path[path.len] = '\0';
        cache->pool[i].pathlen = path.len;
        cache->pool[i].program = program;
    }

    *program = cache->pool[i].program;
    return 0;
}

void template_eval(HTTP_ResponseBuilder builder, int status,
    WL_String path, TemplateCache *cache, WL_Arena *arena,
    SQLiteCache *dbcache, int user_id, int post_id)
{
    http_response_builder_status(builder, status);

    WL_Program program;
    int ret = get_or_create_program(cache, path, arena, &program);
    if (ret < 0) {
        http_response_builder_undo(builder);
        http_response_builder_status(builder, 500);
        http_response_builder_done(builder);
        return;
    }

    //wl_dump_program(program);

    WL_Runtime *rt = wl_runtime_init(arena, program);
    if (rt == NULL) {
        http_response_builder_undo(builder);
        http_response_builder_status(builder, 500);
        http_response_builder_done(builder);
        return;
    }

    for (bool done = false; !done; ) {

        WL_EvalResult result = wl_runtime_eval(rt);
        switch (result.type) {

            case WL_EVAL_DONE:
            http_response_builder_done(builder);
            done = true;
            break;

            case WL_EVAL_ERROR:
            // wl_runtime_error(rt)
            http_response_builder_undo(builder);
            http_response_builder_status(builder, 500);
            http_response_builder_done(builder);
            return;

            case WL_EVAL_SYSVAR:
            push_sysvar(rt, result.str, dbcache, user_id, post_id);
            break;

            case WL_EVAL_SYSCALL:
            push_syscall(rt, result.str, dbcache);
            break;

            case WL_EVAL_OUTPUT:
            http_response_builder_body(builder, (HTTP_String) { result.str.ptr, result.str.len });
            break;

            default:
            break;
        }
    }
}
