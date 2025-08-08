#include "sqlite3.h"
#include "variadic.h"

int sqlite3utils_prepare_impl(sqlite3 *db, sqlite3_stmt **pstmt, const char *fmt, VArgs args);
#define sqlite3utils_prepare(db, pstmt, fmt, ...) sqlite3utils_prepare_impl((db), (pstmt), (fmt), VARGS(__VA_ARGS__))
