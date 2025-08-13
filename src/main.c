#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include "sqlite3.h"
#include "chttp.h"
#include "wl.h"
#include "sqlite3utils.h"

sqlite3 *db;

int load_file(char *file, char **data, long *size)
{
    FILE *f = fopen(file, "rb");
    if (f == NULL) return -1;

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    *data = malloc(*size + 1);

    fread(*data, 1, *size, f);
    (*data)[*size] = '\0';

    fclose(f);
    return 0;
}

static int query_routine(WL_Runtime *rt)
{
    int num_args = wl_arg_count(rt);
    if (num_args == 0)
        return 0;

    WL_String format;
    if (!wl_arg_str(rt, 0, &format))
        return -1;

    sqlite3_stmt *stmt;
    int ret = sqlite3_prepare_v2(db, format.ptr, format.len, &stmt, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    for (int i = 1; i < num_args; i++) {

        int64_t ival;
        double  fval;
        WL_String str;

        if (0) {}
        else if (wl_arg_none(rt, i))
            ret = sqlite3_bind_null  (stmt, i);
        else if (wl_arg_s64(rt, i, &ival))
            ret = sqlite3_bind_int64 (stmt, i, ival);
        else if (wl_arg_f64(rt, i, &fval))
            ret = sqlite3_bind_double(stmt, i, fval);
        else if (wl_arg_str(rt, i, &str))
            ret = sqlite3_bind_text  (stmt, i, str.ptr, str.len, NULL);
        else assert(0);

        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
    }

    wl_push_array(rt, 0);

    while (sqlite3_step(stmt) == SQLITE_ROW) {

        int num_cols = sqlite3_column_count(stmt);
        if (num_cols < 0) {
            assert(0); // TODO
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

    sqlite3_finalize(stmt);
    return 0;
}

int evaluate_template(HTTP_ResponseBuilder builder,
    WL_Program program, WL_Arena arena, int user_id, int post_id)
{
    //wl_dump_program(program);

    WL_Runtime *rt = wl_runtime_init(&arena, program);
    if (rt == NULL)
        return -1;

    for (;;) {

        WL_EvalResult result = wl_runtime_eval(rt);
        switch (result.type) {

            case WL_EVAL_DONE:
            return 0;

            case WL_EVAL_ERROR:
            printf("Error: %s\n", wl_runtime_error(rt).ptr); // TODO
            return -1;

            case WL_EVAL_SYSVAR:
            if (wl_streq(result.str, "login_user_id", -1)) {

                if (user_id < 0)
                    wl_push_none(rt);
                else
                    wl_push_s64(rt, user_id);

            } else if (wl_streq(result.str, "post_id", -1)) {

                if (post_id < 0)
                    wl_push_none(rt);
                else
                    wl_push_s64(rt, post_id);
            }
            break;

            case WL_EVAL_SYSCALL:
            if (wl_streq(result.str, "query", -1)) {
                query_routine(rt);
                break;
            }
            break;

            case WL_EVAL_OUTPUT:
            http_response_builder_body(builder, (HTTP_String) { result.str.ptr, result.str.len });
            break;
        }
    }

    return 0;
}

void evaluate_template_2(HTTP_ResponseBuilder builder, WL_Arena arena, char *file, int user_id, int post_id)
{
    http_response_builder_status(builder, 200);
    http_response_builder_header(builder, HTTP_STR("Content-Type: text/html"));

    WL_Compiler *compiler = wl_compiler_init(&arena);
    if (compiler == NULL) {
        assert(0); // TODO
    }

    char *loaded_files[128];
    int num_loaded_files = 0;

    WL_AddResult result;
    WL_String path = { file, strlen(file) };
    for (int i = 0;; i++) {

        char buf[1<<10];
        if (path.len >= (int) sizeof(buf)) {
            assert(0); // TODO
        }
        memcpy(buf, path.ptr, path.len);
        buf[path.len] = '\0';

        FILE *f = fopen(buf, "rb");
        if (f == NULL) {
            http_response_builder_undo(builder);
            http_response_builder_status(builder, 500);
            http_response_builder_body(builder, HTTP_STR("Couldn't find file '"));
            http_response_builder_body(builder, (HTTP_String) { path.ptr, path.len });
            http_response_builder_body(builder, HTTP_STR("'"));
            http_response_builder_done(builder);
            return;
        }

        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        fseek(f, 0, SEEK_SET);

        char *file_data = malloc(file_size);

        fread(file_data, 1, file_size, f);
        fclose(f);

        result = wl_compiler_add(compiler, (WL_String) { file_data, file_size });

        loaded_files[num_loaded_files++] = file_data;

        if (result.type == WL_ADD_ERROR) {
            printf("Compilation of '%.*s' failed\n", path.len, path.ptr);
            break;
        }

        if (result.type == WL_ADD_LINK)
            break;

        assert(result.type == WL_ADD_AGAIN);
        path = result.path;
    }

    WL_Program program;
    int ret = wl_compiler_link(compiler, &program);

    for (int i = 0; i < num_loaded_files; i++)
        free(loaded_files[i]);

    if (ret < 0) {
        WL_String err = wl_compiler_error(compiler);
        http_response_builder_undo(builder);
        http_response_builder_status(builder, 500);
        http_response_builder_body(builder, (HTTP_String) { err.ptr, err.len });
        http_response_builder_done(builder);
        return;
    }

    if (evaluate_template(builder, program, arena, user_id, post_id) < 0) {
        http_response_builder_undo(builder);
        http_response_builder_status(builder, 500);
        http_response_builder_done(builder);
        return;
    }

    http_response_builder_done(builder);
}

int create_user(HTTP_String name, HTTP_String email, HTTP_String pass)
{
    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare(db, &stmt,
        "INSERT INTO Users(username, email, password) VALUES (?, ?, ?)", name, email, pass);
    if (ret != SQLITE_OK)
        return -500;

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        // TODO: What if the user exists?
        sqlite3_finalize(stmt);
        return -500;
    }

    int64_t tmp = sqlite3_last_insert_rowid(db);
    if (tmp < 0 || tmp > INT_MAX) {
        sqlite3_finalize(stmt);
        return -500;
    }
    int user_id = (int) tmp;

    ret = sqlite3_finalize(stmt);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -500;
    }

    return user_id;
}

int user_exists(HTTP_String name, HTTP_String pass)
{
    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare(db, &stmt,
        "SELECT id FROM Users WHERE username=? AND password=?", name, pass);
    if (ret != SQLITE_OK)
        return -500;

    ret = sqlite3_step(stmt);
    if (ret == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -404;
    }
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -500;
    }

    int user_id = sqlite3_column_int(stmt, 0);
    if (user_id < 0) {
        sqlite3_finalize(stmt);
        return -500;
    }

    ret = sqlite3_finalize(stmt);
    if (ret != SQLITE_OK)
        return -500;

    return user_id;
}

HTTP_String http_getcookie(HTTP_Request *req, HTTP_String name)
{
    // TODO: best-effort implementation

    for (int i = 0; i < req->num_headers; i++) {

        if (!http_streqcase(req->headers[i].name, HTTP_STR("Cookie")))
            continue;

        char *src = req->headers[i].value.ptr;
        int   len = req->headers[i].value.len;
        int   cur = 0;

        // Cookie: name1=value1; name2=value2; name3=value3

        for (;;) {

            while (cur < len && src[cur] == ' ')
                cur++;

            int off = cur;
            while (cur < len && src[cur] != '=')
                cur++;

            HTTP_String cookie_name = { src + off, cur - off };

            if (cur == len)
                break;
            cur++;

            off = cur;
            while (cur < len && src[cur] != ';')
                cur++;

            HTTP_String cookie_value = { src + off, cur - off };

            if (http_streq(name, cookie_name))
                return cookie_value;

            if (cur == len)
                break;
            cur++;
        }
    }

    return HTTP_STR("");
}

void *alloc(WL_Arena *arena, int num, int align)
{
    int pad = -(uintptr_t) (arena->ptr + arena->cur) & (align-1);
    if (arena->len - arena->cur < num + pad)
        return NULL;

    void *ptr = arena->ptr + arena->cur + pad;
    arena->cur += num + pad;

    return ptr;
}

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static int hex_digit_to_int(char c)
{
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - '0';
}

HTTP_String http_getparam(HTTP_String body, HTTP_String str, WL_Arena *arena)
{
    // This is just a best-effort implementation

    char *src = body.ptr;
    int   len = body.len;
    int   cur = 0;

    if (cur < len && src[cur] == '?')
        cur++;

    while (cur < len) {

        HTTP_String name;
        {
            int off = cur;
            while (cur < len && src[cur] != '=' && src[cur] != '&')
                cur++;
            name = (HTTP_String) { src + off, cur - off };
        }

        HTTP_String body = HTTP_STR("");
        if (cur < len) {
            cur++;
            if (src[cur-1] == '=') {
                int off = cur;
                while (cur < len && src[cur] != '&')
                    cur++;
                body = (HTTP_String) { src + off, cur - off };

                if (cur < len)
                    cur++;
            }
        }

        if (http_streq(str, name)) {

            bool percent_encoded = false;
            for (int i = 0; i < body.len; i++)
                if (body.ptr[i] == '+' || body.ptr[i] == '%') {
                    percent_encoded = true;
                    break;
                }

            if (!percent_encoded)
                return body;

            HTTP_String decoded = { alloc(arena, body.len, 1), 0 };
            if (decoded.ptr == NULL)
                return (HTTP_String) { NULL, 0 };

            for (int i = 0; i < body.len; i++) {

                char c = body.ptr[i];
                if (c == '+')
                    c = ' ';
                else {
                    if (body.ptr[i] == '%') {
                        if (body.len - i < 3
                            || !is_hex_digit(body.ptr[i+1])
                            || !is_hex_digit(body.ptr[i+2]))
                            return (HTTP_String) { NULL, 0 };

                        int h = hex_digit_to_int(body.ptr[i+1]);
                        int l = hex_digit_to_int(body.ptr[i+2]);
                        c = (h << 4) | l;

                        i += 2;
                    }
                }

                decoded.ptr[decoded.len++] = c;
            }

            return decoded;
        }
    }

    return HTTP_STR("");
}

#define SESSION_LIMIT 1024
#define USERNAME_LIMIT 64

typedef struct {
    int sess_id;
    int user_id;
} Session;

typedef struct {
    Session sessions[SESSION_LIMIT];
    int count;
    int next_sess_id; // TODO: this should be choosen randomly and on 64 bits
} SessionSet;

void session_set_init(SessionSet *set)
{
    set->count = 0;
    set->next_sess_id = 1;
}

int session_set_add(SessionSet *set, int user_id)
{
    if (set->count == SESSION_LIMIT)
        return -1;
    int sess_id = set->next_sess_id++;
    set->sessions[set->count++] = (Session) {
        .sess_id=sess_id,
        .user_id=user_id,
    };
    return sess_id;
}

void session_set_remove(SessionSet *set, int sess_id)
{
    int i = 0;
    while (i < set->count && set->sessions[i].sess_id != sess_id)
        i++;
    if (i == set->count)
        return;
    set->sessions[i] = set->sessions[--set->count];
}

int session_set_find(SessionSet *set, int sess_id)
{
    int i = 0;
    while (i < set->count && set->sessions[i].sess_id != sess_id)
        i++;
    if (i == set->count)
        return -1;
    return set->sessions[i].user_id;
}

bool valid_name(HTTP_String str)
{
    (void) str; // TODO
    return true;
}

bool valid_email(HTTP_String str)
{
    (void) str; // TODO
    return true;
}

bool valid_pass(HTTP_String str)
{
    (void) str; // TODO
    return true;
}

bool valid_post_title(HTTP_String str)
{
    (void) str; // TODO
    return true;
}

bool valid_post_content(HTTP_String str)
{
    (void) str; // TODO
    return true;
}

bool valid_link(HTTP_String str)
{
    (void) str;
    return true;
}

bool valid_comment_content(HTTP_String str)
{
    (void) str;
    return true;
}

int main(void)
{
    http_global_init();

    printf("%s\n", sqlite3_libversion()); 

    int ret = sqlite3_open(":memory:", &db);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char *schema_data;
    long  schema_size;
    ret = load_file("misc/schema.sql", &schema_data, &schema_size);
    if (ret < 0) {
        printf("Couldn't load schema\n");
        return -1;
    }

    ret = sqlite3_exec(db, schema_data, NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Cannot run schema: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    free(schema_data);

    HTTP_String addr = HTTP_STR("127.0.0.1");
    uint16_t    port = 8080;

    HTTP_Server *server = http_server_init(addr, port);
    if (server == NULL) return -1;

    http_server_set_trace(server, false);

    int pool_cap = 1<<20;
    char *pool = malloc(pool_cap);

    SessionSet sessions;
    session_set_init(&sessions);

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseBuilder builder;

        int ret = http_server_wait(server, &req, &builder);
        if (ret < 0) return -1;

        WL_Arena arena = { pool, pool_cap, 0 };

        //printf("%.*s\n", req->raw.len, req->raw.ptr); // TODO

        // If logged in, these are set to non-negative values
        int sess_id = -1;
        int user_id = -1;

        {
            HTTP_String str = http_getcookie(req, HTTP_STR("sess_id"));
            if (str.len > 0) {

                char tmp[1<<9]; // TODO
                memcpy(tmp, str.ptr, str.len);
                tmp[str.len] = '\0';

                sess_id = atoi(tmp);
                if (sess_id == 0)
                    sess_id = -1;
            }

            user_id = session_set_find(&sessions, sess_id);
        }

        HTTP_String path = req->url.path;
        if (http_streq(path, HTTP_STR("/api/login"))) {

            if (req->method != HTTP_METHOD_POST) {
                http_response_builder_status(builder, 405);
                http_response_builder_done(builder);
                continue;
            }

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            HTTP_String name = http_getparam(req->body, HTTP_STR("username"), &arena);
            HTTP_String pass = http_getparam(req->body, HTTP_STR("password"), &arena);

            name = http_trim(name);
            pass = http_trim(pass);

            if (!valid_name(name) || !valid_pass(pass)) {
                http_response_builder_status(builder, 400);
                http_response_builder_done(builder);
                continue;
            }

            int ret = user_exists(name, pass);
            if (ret < 0) {
                http_response_builder_status(builder, -ret);
                http_response_builder_done(builder);
                continue;
            }
            int user_id = ret;

            int sess_id = session_set_add(&sessions, user_id);
            if (sess_id < 0) {
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }

            char cookie[1<<9];
            int cookie_len = snprintf(cookie, sizeof(cookie), "Set-Cookie: sess_id=%d; Path=/; HttpOnly", sess_id);
            if (cookie_len < 0 || cookie_len >= (int) sizeof(cookie)) {
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }

            http_response_builder_status(builder, 303); // TODO: Whats the correct code here?
            http_response_builder_header(builder, (HTTP_String) { cookie, cookie_len });
            http_response_builder_header(builder, HTTP_STR("Location: /index"));
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/api/signup"))) {

            if (req->method != HTTP_METHOD_POST) {
                http_response_builder_status(builder, 405);
                http_response_builder_done(builder);
                continue;
            }

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            HTTP_String name  = http_getparam(req->body, HTTP_STR("username"),  &arena);
            HTTP_String email = http_getparam(req->body, HTTP_STR("email"),     &arena);
            HTTP_String pass1 = http_getparam(req->body, HTTP_STR("password1"), &arena);
            HTTP_String pass2 = http_getparam(req->body, HTTP_STR("password2"), &arena);

            if (!valid_name(name) || !valid_email(email) || !valid_pass(pass1)) {
                http_response_builder_status(builder, 400);
                http_response_builder_done(builder);
                continue;
            }

            if (!http_streq(pass1, pass2)) {
                http_response_builder_status(builder, 400);
                http_response_builder_done(builder);
                continue;
            }

            int ret = create_user(name, email, pass1);
            if (ret < 0) {
                http_response_builder_status(builder, -ret);
                http_response_builder_done(builder);
                continue;
            }
            user_id = ret;

            int sess_id = session_set_add(&sessions, user_id);
            if (sess_id < 0) {
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }

            char cookie[1<<9];
            int cookie_len = snprintf(cookie, sizeof(cookie), "Set-Cookie: sess_id=%d; Path=/; HttpOnly", sess_id);
            if (cookie_len < 0 || cookie_len >= (int) sizeof(cookie)) {
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }

            http_response_builder_status(builder, 303); // TODO: Whats the correct code here?
            http_response_builder_header(builder, (HTTP_String) { cookie, cookie_len });
            http_response_builder_header(builder, HTTP_STR("Location: /index"));
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/api/logout"))) {

            if (sess_id != -1)
                session_set_remove(&sessions, sess_id);

            http_response_builder_status(builder, 303); // TODO: Whats the correct code here?
            http_response_builder_header(builder, HTTP_STR("Set-Cookie: sess_id=; Path=/; HttpOnly"));
            http_response_builder_header(builder, HTTP_STR("Location: /index"));
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/api/post"))) {

            if (req->method != HTTP_METHOD_POST) {
                http_response_builder_status(builder, 405);
                http_response_builder_done(builder);
                continue;
            }

            if (user_id == -1) {
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            HTTP_String title   = http_getparam(req->body, HTTP_STR("title"),   &arena);
            HTTP_String link    = http_getparam(req->body, HTTP_STR("link"),    &arena);
            HTTP_String content = http_getparam(req->body, HTTP_STR("content"), &arena);

            title   = http_trim(title);
            link    = http_trim(link);
            content = http_trim(content);

            if (!valid_post_title(title) || !valid_link(link) || !valid_post_content(content)) {
                assert(0); // TODO
            }

            if (content.len == 0 && link.len == 0) {
                assert(0); // TODO
            }

            bool is_link = false;
            if (link.len > 0) {
                is_link = true;
                content = link;
            }

            sqlite3_stmt *stmt;
            int ret = sqlite3utils_prepare(db, &stmt, "INSERT INTO Posts(author, title, is_link, content) VALUES (?, ?, ?, ?)", user_id, title, is_link, content);
            if (ret != SQLITE_OK) {
                assert(0); // TODO
            }

            ret = sqlite3_step(stmt);
            if (ret != SQLITE_DONE) {
                assert(0); // TODO
            }

            ret = sqlite3_finalize(stmt);
            if (ret != SQLITE_OK) {
                assert(0); // TODO
            }

            int64_t tmp = sqlite3_last_insert_rowid(db);
            if (tmp < 0 || tmp > INT_MAX) {
                assert(0); // TODO
            }
            int post_id = (int) tmp;

            char location[1<<9];
            ret = snprintf(location, sizeof(location), "Location: /post?id=%d", post_id);
            if (ret < 0 || ret >= (int) sizeof(location)) {
                assert(0); // TODO
            }

            http_response_builder_status(builder, 303);
            http_response_builder_header(builder, (HTTP_String) { location, ret });
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/api/comment"))) {

            if (req->method != HTTP_METHOD_POST) {
                http_response_builder_status(builder, 405);
                http_response_builder_done(builder);
                continue;
            }

            if (user_id == -1) {
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            HTTP_String parent_post_str = http_getparam(req->body, HTTP_STR("parent_post"), &arena);
            HTTP_String parent_comment_str = http_getparam(req->body, HTTP_STR("parent_comment"), &arena);
            HTTP_String content = http_getparam(req->body, HTTP_STR("content"), &arena);

            int parent_post;
            {
                char buf[32];
                if (parent_post_str.len >= (int) sizeof(buf)) {
                    assert(0); // TODO
                }
                memcpy(buf, parent_post_str.ptr, parent_post_str.len);
                buf[parent_post_str.len] = '\0';

                parent_post = atoi(buf);
                if (parent_post == 0) {
                    assert(0); // TODO
                }
            }

            int parent_comment;
            {
                char buf[32];
                if (parent_comment_str.len >= (int) sizeof(buf))
                    parent_comment = -1;
                else {
                    memcpy(buf, parent_comment_str.ptr, parent_comment_str.len);
                    buf[parent_comment_str.len] = '\0';

                    parent_comment = atoi(buf);
                    if (parent_comment == 0)
                        parent_comment = -1;
                }
            }

            content = http_trim(content);
            if (!valid_comment_content(content)) {
                assert(0); // TODO
            }

            if (content.len == 0) {
                assert(0); // TODO
            }

            int ret;
            sqlite3_stmt *stmt;
            if (parent_comment == -1)
                ret = sqlite3utils_prepare(db, &stmt, "INSERT INTO Comments(author, content, parent_post) VALUES (?, ?, ?)", user_id, content, parent_post);
            else
                ret = sqlite3utils_prepare(db, &stmt, "INSERT INTO Comments(author, content, parent_post, parent_comment) VALUES (?, ?, ?, ?)", user_id, content, parent_post, parent_comment);
            if (ret != SQLITE_OK) {
                assert(0); // TODO
            }

            ret = sqlite3_step(stmt);
            if (ret != SQLITE_DONE) {
                assert(0); // TODO
            }

            ret = sqlite3_finalize(stmt);
            if (ret != SQLITE_OK) {
                assert(0); // TODO
            }

            char location[1<<9];
            ret = snprintf(location, sizeof(location), "Location: /post?id=%d", parent_post);
            if (ret < 0 || ret >= (int) sizeof(location)) {
                assert(0); // TODO
            }

            http_response_builder_status(builder, 303);
            http_response_builder_header(builder, (HTTP_String) { location, ret });
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/index"))) {

            evaluate_template_2(builder, arena, "pages/index.wl", user_id, -1);

        } else if (http_streq(path, HTTP_STR("/write"))) {

            if (user_id == -1) {
                // Not logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            evaluate_template_2(builder, arena, "pages/write.wl", user_id, -1);

        } else if (http_streq(path, HTTP_STR("/login"))) {

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            evaluate_template_2(builder, arena, "pages/login.wl", user_id, -1);

        } else if (http_streq(path, HTTP_STR("/signup"))) {

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            evaluate_template_2(builder, arena, "pages/signup.wl", user_id, -1);

        } else if (http_streq(path, HTTP_STR("/post"))) {

            HTTP_String idstr = http_getparam(req->url.query, HTTP_STR("id"), &arena);

            char buf[32];
            if (idstr.len == 0 || idstr.len >= (int) sizeof(buf)) {
                printf("post id [%.*s] is not defined\n", idstr.len, idstr.ptr); // TODO
                evaluate_template_2(builder, arena, "pages/notfound.wl", user_id, -1);
                continue;
            }
            memcpy(buf, idstr.ptr, idstr.len);
            buf[idstr.len] = '\0';

            int post_id = atoi(buf);
            if (post_id == 0) {
                printf("Invalid post id [%s]\n", buf);
                evaluate_template_2(builder, arena, "pages/notfound.wl", user_id, -1);
                continue;
            }

            sqlite3_stmt *stmt;
            int ret = sqlite3utils_prepare(db, &stmt, "SELECT COUNT(*) FROM Posts WHERE id=?", post_id);
            if (ret != SQLITE_OK) {
                assert(0); // TODO
            }

            ret = sqlite3_step(stmt);
            if (ret != SQLITE_ROW) {
                assert(0); // TODO
            }
            int64_t num = sqlite3_column_int64(stmt, 0);

            ret = sqlite3_finalize(stmt);
            if (ret != SQLITE_OK) {
                assert(0); // TODO
            }

            if (num < 0) {
                assert(0); // TODO
            }

            if (num == 0)
                evaluate_template_2(builder, arena, "pages/notfound.wl", user_id, -1);
            else
                evaluate_template_2(builder, arena, "pages/post.wl", user_id, post_id);

        } else {

            evaluate_template_2(builder, arena, "pages/notfound.wl", user_id, -1);
        }
    }

    sqlite3_close(db);
    http_server_free(server);
    http_global_free();
    return 0;
}
