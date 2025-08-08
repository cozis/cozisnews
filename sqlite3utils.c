#include <stdio.h>
#include <stddef.h>
#include "sqlite3utils.h"

int sqlite3utils_prepare_impl(sqlite3 *db, sqlite3_stmt **pstmt, const char *fmt, VArgs args)
{
    sqlite3_stmt *stmt;
    int ret = sqlite3_prepare_v2(db, fmt, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s (%s:%d)\n", sqlite3_errmsg(db), __FILE__, __LINE__);
        return ret;
    }

    for (int i = 0; i < args.len; i++) {
        VArg arg = args.ptr[i];
        switch (arg.type) {
            case VARG_TYPE_C  : ret = sqlite3_bind_text(stmt, i+1, &arg.c, 1, NULL); break;
            case VARG_TYPE_S  : ret = sqlite3_bind_int(stmt, i+1, arg.s);     break;
            case VARG_TYPE_I  : ret = sqlite3_bind_int(stmt, i+1, arg.i);     break;
            case VARG_TYPE_L  : ret = sqlite3_bind_int64(stmt, i+1, arg.l);   break;
            case VARG_TYPE_LL : ret = sqlite3_bind_int64(stmt, i+1, arg.ll);  break;
            case VARG_TYPE_SC : ret = sqlite3_bind_int(stmt, i+1, arg.sc);    break;
            case VARG_TYPE_SS : ret = sqlite3_bind_int(stmt, i+1, arg.ss);    break;
            case VARG_TYPE_SI : ret = sqlite3_bind_int(stmt, i+1, arg.si);    break;
            case VARG_TYPE_SL : ret = sqlite3_bind_int64(stmt, i+1, arg.sl);  break;
            case VARG_TYPE_SLL: ret = sqlite3_bind_int(stmt, i+1, arg.sll);   break;
            case VARG_TYPE_UC : ret = sqlite3_bind_int(stmt, i+1, arg.uc);    break;
            case VARG_TYPE_US : ret = sqlite3_bind_int(stmt, i+1, arg.us);    break;
            case VARG_TYPE_UI : ret = sqlite3_bind_int64(stmt, i+1, arg.ui);  break;
            case VARG_TYPE_UL : ret = sqlite3_bind_int64(stmt, i+1, arg.ul);  break;
            case VARG_TYPE_ULL: ret = sqlite3_bind_int64(stmt, i+1, arg.ull); break;
            case VARG_TYPE_F  : ret = sqlite3_bind_double(stmt, i+1, arg.f);  break;
            case VARG_TYPE_D  : ret = sqlite3_bind_double(stmt, i+1, arg.d);  break;
            case VARG_TYPE_B  : ret = sqlite3_bind_int(stmt, i+1, arg.b);     break;
            case VARG_TYPE_STR: ret = sqlite3_bind_text(stmt, i+1, arg.str.ptr, arg.str.len, NULL); break;
        }
        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s (%s:%d)\n", sqlite3_errmsg(db), __FILE__, __LINE__);
            sqlite3_finalize(stmt);
            return ret;
        }
    }

    *pstmt = stmt;
    return SQLITE_OK;
}