#ifndef SQLITE3UTILS_INCLUDED
#define SQLITE3UTILS_INCLUDED

#include "sqlite3.h"
#include "variadic.h"

#define sqlite3utils_prepare_and_bind(cache, pstmt, fmt, ...) sqlite3utils_prepare_and_bind_impl((cache), (pstmt), (fmt), VARGS(__VA_ARGS__))

typedef struct SQLiteCache SQLiteCache;

SQLiteCache* sqlite_cache_init(sqlite3 *db, int capacity_log2);
void         sqlite_cache_free(SQLiteCache *cache);
sqlite3*     sqlite_cache_getdb(SQLiteCache *cache);

int sqlite3utils_prepare(SQLiteCache *cache,
    sqlite3_stmt **pstmt, const char *fmt, int fmtlen);

int sqlite3utils_prepare_and_bind_impl(SQLiteCache *cache,
    sqlite3_stmt **pstmt, const char *fmt, VArgs args);

#endif // SQLITE3UTILS_INCLUDED