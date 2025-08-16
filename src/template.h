#ifndef TEMPLATE_INCLUDED
#define TEMPLATE_INCLUDED

#include "wl.h"
#include "chttp.h"
#include "sqlite3utils.h"

typedef struct TemplateCache TemplateCache;
TemplateCache *template_cache_init(int capacity_log2);
void           template_cache_free(TemplateCache *cache);

void template_eval(HTTP_ResponseBuilder builder, int status,
    WL_String path, TemplateCache *cache, WL_Arena *arena,
    SQLiteCache *dbcache, int user_id, int post_id);

#endif // TEMPLATE_INCLUDED