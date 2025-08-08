#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include "sqlite3.h"
#include "chttp.h"
#include "WL.h"
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

static int query_routine(WL_State *state)
{
    long long num_args;
    if (!WL_popint(state, &num_args)) {
        assert(0); // TODO
    }
    if (num_args == 0) {
        assert(0); // TODO
    }

    WL_String format;
    if (!WL_peekstr(state, -num_args, &format)) {
        assert(0); // TODO
    }

    sqlite3_stmt *res;
    int ret = sqlite3_prepare_v2(db, format.ptr, format.len, &res, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        assert(0); // TODO
    }

    for (int i = 0; i < num_args-1; i++) {

        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
            assert(0); // TODO
        }

        if (WL_peeknone(state, -num_args + i + 1)) {
            ret = sqlite3_bind_null(res, i+1);
            continue;
        }

        long long ival;
        if (WL_peekint(state, -num_args + i + 1, &ival)) {
            ret = sqlite3_bind_int64(res, i+1, ival);
            continue;
        }

        float fval;
        if (WL_peekfloat(state, -num_args + i + 1, &fval)) {
            ret = sqlite3_bind_double(res, i+1, fval);
            continue;
        }

        WL_String str;
        if (WL_peekstr(state, -num_args + i + 1, &str)) {
            ret = sqlite3_bind_text(res, i+1, str.ptr, str.len, NULL);
            continue;
        }

        break;
    }

    ret = sqlite3_step(res);
    if (ret == SQLITE_DONE) {
        WL_pushnone(state);
    } else if (ret != SQLITE_ROW) {
        WL_pushnone(state);
    } else {

        WL_pusharray(state, 0);
        do {

            int num_cols = sqlite3_column_count(res);
            if (num_cols < 0) {
                assert(0); // TODO
            }

            WL_pushmap(state, 0);

            for (int i = 0; i < num_cols; i++) {
                ret = sqlite3_column_type(res, i);
                switch (ret) {

                    case SQLITE_INTEGER:
                    {
                        int64_t x = sqlite3_column_int64(res, i);
                        WL_pushint(state, x);
                    }
                    break;

                    case SQLITE_FLOAT:
                    {
                        double x = sqlite3_column_double(res, i);
                        WL_pushfloat(state, x);
                    }
                    break;

                    case SQLITE_TEXT:
                    {
                        const void *x = sqlite3_column_text(res, i);
                        int n = sqlite3_column_bytes(res, i);
                        WL_pushstr(state, (WL_String) { (char*) x, n });
                    }
                    break;

                    case SQLITE_BLOB:
                    {
                        const void *x = sqlite3_column_blob(res, i);
                        int n = sqlite3_column_bytes(res, i);
                        WL_pushstr(state, (WL_String) { (char*) x, n });
                    }
                    break;

                    case SQLITE_NULL:
                    {
                        WL_pushnone(state);
                    }
                    break;
                }

                const char *name = sqlite3_column_name(res, i);

                WL_pushstr(state, (WL_String) { (char*) name, strlen(name) });
                WL_insert(state);
            }

            WL_append(state);

        } while (sqlite3_step(res) == SQLITE_ROW);
    }

    WL_pushint(state, 1);

    sqlite3_finalize(res);
    return 0;
}

int evaluate_template(HTTP_ResponseBuilder builder,
    WL_Program program, WL_Arena arena,
    char *err, int errmax, int user_id)
{
    //WL_dump_program(program);

    WL_State *state = WL_State_init(&arena, program, err, errmax);
    if (state == NULL)
        return -1;

    WL_State_trace(state, 0);

    for (;;) {

        WL_Result result = WL_eval(state);
        switch (result.type) {

            case WL_DONE:
            WL_State_free(state);
            return 0;

            case WL_ERROR:
            WL_State_free(state);
            return -1;

            case WL_VAR:
            if (WL_streq(result.str, "login_user_id", -1)) {
                if (user_id < 0)
                    WL_pushnone(state);
                else
                    WL_pushint(state, user_id);
            }
            break;

            case WL_CALL:
            if (WL_streq(result.str, "query", -1)) {
                query_routine(state);
                break;
            }
            break;

            case WL_OUTPUT:
            http_response_builder_body(builder, (HTTP_String) { result.str.ptr, result.str.len });
            break;
        }
    }

    return 0;
}

void evaluate_template_2(HTTP_ResponseBuilder builder, WL_Arena arena, char *file, int user_id)
{
    http_response_builder_status(builder, 200);
    http_response_builder_header(builder, HTTP_STR("Content-Type: text/html"));

    WL_Compiler *compiler = WL_Compiler_init(&arena);
    if (compiler == NULL) {
        assert(0); // TODO
    }

    char *loaded_files[128];
    int num_loaded_files = 0;

    WL_CompileResult result;
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

        result = WL_compile(compiler, path, (WL_String) { file_data, file_size });

        loaded_files[num_loaded_files++] = file_data;

        if (result.type == WL_COMPILE_RESULT_ERROR) {
            printf("Compilation of '%.*s' failed\n", path.len, path.ptr);
            break;
        }

        if (result.type == WL_COMPILE_RESULT_DONE)
            break;

        assert(result.type == WL_COMPILE_RESULT_FILE);
        path = result.path;
    }

    for (int i = 0; i < num_loaded_files; i++)
        free(loaded_files[i]);

    WL_Compiler_free(compiler);

    if (result.type == WL_COMPILE_RESULT_ERROR) {
        http_response_builder_undo(builder);
        http_response_builder_status(builder, 500);
        http_response_builder_body(builder, HTTP_STR("Couldn't compile the template"));
        http_response_builder_done(builder);
        return;
    }
    WL_Program program = result.program;

    char err[1<<9];
    if (evaluate_template(builder, program, arena, err, (int) sizeof(err), user_id) < 0) {
        http_response_builder_undo(builder);
        http_response_builder_status(builder, 500);
        http_response_builder_body(builder, (HTTP_String) { err, (int) strlen(err) });
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

HTTP_String http_getparam(HTTP_String body, HTTP_String str)
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

        if (http_streq(str, name))
            return body;
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
    ret = load_file("schema.sql", &schema_data, &schema_size);
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

    WL_Arena arena = { pool, pool_cap, 0 };

    SessionSet sessions;
    session_set_init(&sessions);

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseBuilder builder;

        int ret = http_server_wait(server, &req, &builder);
        if (ret < 0) return -1;

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

            HTTP_String name = http_getparam(req->body, HTTP_STR("username"));
            HTTP_String pass = http_getparam(req->body, HTTP_STR("password"));

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

            HTTP_String name  = http_getparam(req->body, HTTP_STR("username"));
            HTTP_String email = http_getparam(req->body, HTTP_STR("email"));
            HTTP_String pass1 = http_getparam(req->body, HTTP_STR("password1"));
            HTTP_String pass2 = http_getparam(req->body, HTTP_STR("password2"));

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
                assert(0); // TODO
            }

            if (user_id == -1) {
                assert(0); // TODO
            }

            HTTP_String title   = http_getparam(req->body, HTTP_STR("title"));
            HTTP_String content = http_getparam(req->body, HTTP_STR("content"));

            title   = http_trim(title);
            content = http_trim(content);

            if (!valid_post_title(title) || !valid_post_content(content)) {
                assert(0); // TODO
            }

            // TODO

        } else if (http_streq(path, HTTP_STR("/index"))) {

            evaluate_template_2(builder, arena, "pages/index.wl", user_id);

        } else if (http_streq(path, HTTP_STR("/write"))) {

            if (user_id == -1) {
                // Not logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            evaluate_template_2(builder, arena, "pages/write.wl", user_id);

        } else if (http_streq(path, HTTP_STR("/login"))) {

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            evaluate_template_2(builder, arena, "pages/login.wl", user_id);

        } else if (http_streq(path, HTTP_STR("/signup"))) {

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            evaluate_template_2(builder, arena, "pages/signup.wl", user_id);

        } else if (http_streq(path, HTTP_STR("/thread"))) {

            evaluate_template_2(builder, arena, "pages/thread.wl", user_id);

        } else {

            evaluate_template_2(builder, arena, "pages/notfound.wl", user_id);
        }
    }

    sqlite3_close(db);
    http_server_free(server);
    http_global_free();
    return 0;
}
