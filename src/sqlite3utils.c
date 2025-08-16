#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite3utils.h"

typedef struct {
    char *str;
    int   len;
    sqlite3_stmt *stmt;
} Prepped;

struct SQLiteCache {
    sqlite3 *db;
    int count;
    int capacity_log2;
    Prepped items[];
};

SQLiteCache *sqlite_cache_init(sqlite3 *db, int capacity_log2)
{
    SQLiteCache *cache = malloc(sizeof(SQLiteCache) + (1 << capacity_log2) * sizeof(Prepped));
    if (cache == NULL)
        return NULL;

    cache->db = db;
    cache->count = 0;
    cache->capacity_log2 = capacity_log2;

    for (int i = 0; i < (1 << capacity_log2); i++)
        cache->items[i].stmt = NULL;

    return cache;
}

void sqlite_cache_free(SQLiteCache *cache)
{
    for (int i = 0; i < (1 << cache->capacity_log2); i++) {
        sqlite3_stmt *stmt = cache->items[i].stmt;
        if (stmt) {
            free(cache->items[i].str);
            sqlite3_finalize(stmt);
        }
    }
    free(cache);
}

sqlite3 *sqlite_cache_getdb(SQLiteCache *cache)
{
    return cache->db;
}

static unsigned long djb2(char *src, int len)
{
    char *ptr = src;
    char *end = src + len;

    unsigned long hash = 5381;
    int c;
    while (ptr < end && (c = *ptr++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

static int lookup(SQLiteCache *cache, char *fmt, int fmtlen)
{
    int mask = (1 << cache->capacity_log2) - 1;
    int hash = djb2(fmt, fmtlen);
    int i = hash & mask;
    int perturb = hash;
    for (;;) {

        if (cache->items[i].stmt == NULL)
            return i;

        if (cache->items[i].len == fmtlen && !memcmp(cache->items[i].str, fmt, fmtlen))
            return i;

        perturb >>= 5;
        i = (i * 5 + 1 + perturb) & mask;
    }

    return -1;
}

int sqlite3utils_prepare(SQLiteCache *cache, sqlite3_stmt **pstmt, const char *fmt, int fmtlen)
{
    if (fmtlen < 0)
        fmtlen = strlen(fmt);

    int i = lookup(cache, fmt, fmtlen);
    if (cache->items[i].stmt == NULL) {

        printf("Preparing statement [%.*s]\n", fmtlen, fmt); // TODO

        sqlite3_stmt *stmt;
        int ret = sqlite3_prepare_v2(cache->db, fmt, -1, &stmt, NULL);
        if (ret != SQLITE_OK) {
            //fprintf(stderr, "Failed to prepare statement: %s (%s:%d)\n", sqlite3_errmsg(db), __FILE__, __LINE__);
            return ret;
        }

        char *cpy = malloc(fmtlen);
        if (cpy == NULL) {
            sqlite3_finalize(stmt);
            return SQLITE_NOMEM;
        }
        memcpy(cpy, fmt, fmtlen);

        cache->items[i].str = cpy;
        cache->items[i].len = fmtlen;
        cache->items[i].stmt = stmt;
    }
    sqlite3_stmt *stmt = cache->items[i].stmt;

    *pstmt = stmt;
    return SQLITE_OK;
}

int sqlite3utils_prepare_and_bind_impl(SQLiteCache *cache,
    sqlite3_stmt **pstmt, const char *fmt, VArgs args)
{
    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare(cache, &stmt, fmt, strlen(fmt));
    if (ret != SQLITE_OK)
        return ret;

    for (int i = 0; i < args.len; i++) {
        VArg arg = args.ptr[i];
        switch (arg.type) {
            case VARG_TYPE_C  : ret = sqlite3_bind_text  (stmt, i+1, &arg.c, 1, NULL); break;
            case VARG_TYPE_S  : ret = sqlite3_bind_int   (stmt, i+1, arg.s);   break;
            case VARG_TYPE_I  : ret = sqlite3_bind_int   (stmt, i+1, arg.i);   break;
            case VARG_TYPE_L  : ret = sqlite3_bind_int64 (stmt, i+1, arg.l);   break;
            case VARG_TYPE_LL : ret = sqlite3_bind_int64 (stmt, i+1, arg.ll);  break;
            case VARG_TYPE_SC : ret = sqlite3_bind_int   (stmt, i+1, arg.sc);  break;
            case VARG_TYPE_SS : ret = sqlite3_bind_int   (stmt, i+1, arg.ss);  break;
            case VARG_TYPE_SI : ret = sqlite3_bind_int   (stmt, i+1, arg.si);  break;
            case VARG_TYPE_SL : ret = sqlite3_bind_int64 (stmt, i+1, arg.sl);  break;
            case VARG_TYPE_SLL: ret = sqlite3_bind_int   (stmt, i+1, arg.sll); break;
            case VARG_TYPE_UC : ret = sqlite3_bind_int   (stmt, i+1, arg.uc);  break;
            case VARG_TYPE_US : ret = sqlite3_bind_int   (stmt, i+1, arg.us);  break;
            case VARG_TYPE_UI : ret = sqlite3_bind_int64 (stmt, i+1, arg.ui);  break;
            case VARG_TYPE_UL : ret = sqlite3_bind_int64 (stmt, i+1, arg.ul);  break;
            case VARG_TYPE_ULL: ret = sqlite3_bind_int64 (stmt, i+1, arg.ull); break;
            case VARG_TYPE_F  : ret = sqlite3_bind_double(stmt, i+1, arg.f);   break;
            case VARG_TYPE_D  : ret = sqlite3_bind_double(stmt, i+1, arg.d);   break;
            case VARG_TYPE_B  : ret = sqlite3_bind_int   (stmt, i+1, arg.b);   break;
            case VARG_TYPE_STR: ret = sqlite3_bind_text  (stmt, i+1, arg.str.ptr, arg.str.len, NULL); break;
        }
        if (ret != SQLITE_OK) {
            sqlite3_reset(stmt);
            return ret;
        }
    }

    *pstmt = stmt;
    return SQLITE_OK;
}