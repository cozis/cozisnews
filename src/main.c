#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include "chttp.h"
#include "bcrypt.h"
#include "sqlite3.h"
#include "sqlite3utils.h"
#include "template.h"

#define WL_STR(X) ((WL_String) { (X), (int) sizeof(X)-1})

#define HTML_STR(X) html_str(HTTP_STR(#X))

static HTTP_String html_str(HTTP_String str)
{
    str = http_trim(str);
    if (str.len > 0 && str.ptr[0] == '(') {
        str.ptr++;
        str.len--;
    }
    if (str.len > 0 && str.ptr[str.len-1] == ')')
        str.len--;
    return str;
}

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

int create_user(SQLiteCache *dbcache, HTTP_String name, HTTP_String email, HTTP_String pass)
{
    PasswordHash hash;
    int ret = hash_password(pass.ptr, pass.len, 12, &hash);
    if (ret) return -500;

    sqlite3_stmt *stmt;
    ret = sqlite3utils_prepare_and_bind(dbcache, &stmt,
        "INSERT INTO Users(username, email, hash) VALUES (?, ?, ?)", name, email, ((HTTP_String) { hash.data, strlen(hash.data) }));
    if (ret != SQLITE_OK)
        return -500;

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(sqlite_cache_getdb(dbcache)));
        // TODO: What if the user exists?
        sqlite3_reset(stmt);
        return -500;
    }

    int64_t tmp = sqlite3_last_insert_rowid(sqlite_cache_getdb(dbcache));
    if (tmp < 0 || tmp > INT_MAX) {
        sqlite3_reset(stmt);
        return -500;
    }
    int user_id = (int) tmp;

    ret = sqlite3_reset(stmt);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(sqlite_cache_getdb(dbcache)));
        sqlite3_reset(stmt);
        return -500;
    }

    return user_id;
}

int user_exists(SQLiteCache *dbcache, HTTP_String name, HTTP_String pass)
{
    sqlite3_stmt *stmt;
    int ret = sqlite3utils_prepare_and_bind(dbcache, &stmt,
        "SELECT id, hash FROM Users WHERE username=?", name);
    if (ret != SQLITE_OK)
        return -500;

    ret = sqlite3_step(stmt);
    if (ret == SQLITE_DONE) {
        sqlite3_reset(stmt);
        return -404;
    }
    if (ret != SQLITE_ROW) {
        sqlite3_reset(stmt);
        return -500;
    }

    int user_id = sqlite3_column_int(stmt, 0);
    if (user_id < 0) {
        sqlite3_reset(stmt);
        return -500;
    }

    const char *rawhash = (const char*) sqlite3_column_text(stmt, 1);
    if (rawhash == NULL) {
        sqlite3_reset(stmt);
        return -500;
    }
    int rawhashlen = sqlite3_column_bytes(stmt, 1);

    PasswordHash hash;
    if (rawhashlen >= sizeof(hash.data)) {
        sqlite3_reset(stmt);
        return -500;
    }
    strcpy(hash.data, rawhash);

    ret = check_password(pass.ptr, pass.len, hash);
    if (ret < 0) {
        sqlite3_reset(stmt);
        return -500;
    }
    if (ret > 0) {
        sqlite3_reset(stmt);
        return -400;
    }

    ret = sqlite3_reset(stmt);
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

static void *alloc(WL_Arena *arena, int num, int align)
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

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

int http_getparami(HTTP_String body, HTTP_String str, WL_Arena *arena)
{
    HTTP_String out = http_getparam(body, str, arena);
    if (out.len == 0 || !is_digit(out.ptr[0]))
        return -1;
    int cur = 0;
    int buf = 0;
    do {
        int d = out.ptr[cur++] - '0';
        if (buf > (INT_MAX - d) / 10)
            return -1;
        buf = buf * 10 + d;
    } while (cur < out.len && is_digit(out.ptr[cur]));

    return buf;
}

#define SESSION_LIMIT 1024
#define USERNAME_LIMIT 64

#define RAW_SESSION_TOKEN_SIZE 32
#define RAW_CSRF_TOKEN_SIZE 32

#define SESSION_TOKEN_SIZE (2 * RAW_SESSION_TOKEN_SIZE)
#define CSRF_TOKEN_SIZE (2 * RAW_CSRF_TOKEN_SIZE)

typedef struct {
    int  user_id;
    char raw_sess_token[RAW_SESSION_TOKEN_SIZE];
    char raw_csrf_token[RAW_CSRF_TOKEN_SIZE];
} Session;

typedef struct {
    Session sessions[SESSION_LIMIT];
    int count;
} SessionSet;

#include "random.h"

void session_set_init(SessionSet *set)
{
    set->count = 0;
}

typedef struct {
    char data[SESSION_TOKEN_SIZE];
} SessionToken;

typedef struct {
    char data[CSRF_TOKEN_SIZE];
} CSRFToken;

static void unpack_token(char *src, int srclen, char *dst, int dstlen)
{
    assert(srclen == 2 * dstlen);

    for (int i = 0; i < srclen; i++) {
        static const char table[] = "0123456789abcdef";
        int low  = (src[i] & 0x0F) >> 0;
        int high = (src[i] & 0xF0) >> 4;
        dst[(i << 1) | 0] = table[high];
        dst[(i << 1) | 1] = table[low];
    }
}

static int pack_token(char *src, int srclen, char *dst, int dstlen)
{
    if (srclen & 1)
        return -1;

    assert(2 * srclen == dstlen);

    for (int i = 0; i < srclen; i += 2) {
        int high = src[i+0];
        int low  = src[i+1];
        if (!is_hex_digit(high) || !is_hex_digit(low))
            return -1;
        dst[i] = (hex_digit_to_int(high) << 4) | (hex_digit_to_int(low) << 0);
    }

    return 0;
}

int session_set_add(SessionSet *set, int user_id, SessionToken *sess_token, CSRFToken *csrf_token)
{
    if (set->count == SESSION_LIMIT)
        return -1;

    Session *session = &set->sessions[set->count];

    int ret;
    ret = generate_random_bytes(session->raw_sess_token, (int) sizeof(session->raw_sess_token));
    if (ret) return -1;

    ret = generate_random_bytes(session->raw_csrf_token, (int) sizeof(session->raw_csrf_token));
    if (ret) return -1;

    session->user_id = user_id;

    unpack_token(
        session->raw_csrf_token, (int) sizeof(session->raw_csrf_token),
        csrf_token->data,        (int) sizeof(csrf_token->data)
    );

    unpack_token(
        session->raw_sess_token, (int) sizeof(session->raw_sess_token),
        sess_token->data,        (int) sizeof(sess_token->data)
    );

    set->count++;
    return 0;
}

void session_set_remove(SessionSet *set, SessionToken sess_token)
{
    char raw_sess_token[RAW_SESSION_TOKEN_SIZE];
    pack_token(
        sess_token.data, (int) sizeof(sess_token.data),
        raw_sess_token,   (int) sizeof(raw_sess_token)
    );

    int i = 0;
    while (i < set->count && memcmp(set->sessions[i].raw_sess_token, raw_sess_token, RAW_SESSION_TOKEN_SIZE))
        i++;
    if (i == set->count)
        return;
    set->sessions[i] = set->sessions[--set->count];
}

int session_set_find(SessionSet *set, SessionToken sess_token)
{
char raw_sess_token[RAW_SESSION_TOKEN_SIZE];
    pack_token(
        sess_token.data, (int) sizeof(sess_token.data),
        raw_sess_token,   (int) sizeof(raw_sess_token)
    );

    int i = 0;
    while (i < set->count && memcmp(set->sessions[i].raw_sess_token, raw_sess_token, RAW_SESSION_TOKEN_SIZE))
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

    sqlite3 *db;
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

    TemplateCache *tpcache = template_cache_init(4);
    SQLiteCache   *dbcache = sqlite_cache_init(db, 5);


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
        SessionToken sess_token;
        int user_id = -1;

        {
            HTTP_String str = http_getcookie(req, HTTP_STR("sess_id"));
            if (str.len == SESSION_TOKEN_SIZE) {
                char tmp[RAW_SESSION_TOKEN_SIZE];
                int ret = pack_token(str.ptr, str.len, tmp, (int) sizeof(tmp));
                if (ret) {
                    memcpy(sess_token.data, str.ptr, str.len);
                    user_id = session_set_find(&sessions, sess_token);
                }
            }
        }

        HTTP_String path = req->url.path;
        if (http_streq(path, HTTP_STR("/api/login"))) {

            if (req->method != HTTP_METHOD_POST) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid request method
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 200);
                http_response_builder_header(builder, HTTP_STR("HX-Redirect: /index"));
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        You are already logged in
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            HTTP_String name = http_getparam(req->body, HTTP_STR("username"), &arena);
            HTTP_String pass = http_getparam(req->body, HTTP_STR("password"), &arena);

            name = http_trim(name);
            pass = http_trim(pass);

            if (!valid_name(name) || !valid_pass(pass)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid credentials
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            int ret = user_exists(dbcache, name, pass);
            if (ret < 0) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid credentials
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }
            int user_id = ret;

            CSRFToken csrf_token;
            SessionToken sess_token;
            if (session_set_add(&sessions, user_id, &sess_token, &csrf_token) < 0) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            char cookie[1<<9];
            int cookie_len = snprintf(cookie, sizeof(cookie), "Set-Cookie: sess_id=%.*s; Path=/; HttpOnly", (int) sizeof(sess_token.data)-1, sess_token.data);
            if (cookie_len < 0 || cookie_len >= (int) sizeof(cookie)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            http_response_builder_status(builder, 200); // TODO: Whats the correct code here?
            http_response_builder_header(builder, (HTTP_String) { cookie, cookie_len });
            http_response_builder_header(builder, HTTP_STR("HX-Redirect: /index"));
            http_response_builder_body(builder, HTML_STR((
                <div class="success">
                    Welcome back!
                </div>
            )));
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/api/signup"))) {

            if (req->method != HTTP_METHOD_POST) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid request method
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 200);
                http_response_builder_header(builder, HTTP_STR("HX-Redirect: /index"));
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        You are already logged in
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            HTTP_String name  = http_getparam(req->body, HTTP_STR("username"),  &arena);
            HTTP_String email = http_getparam(req->body, HTTP_STR("email"),     &arena);
            HTTP_String pass1 = http_getparam(req->body, HTTP_STR("password1"), &arena);
            HTTP_String pass2 = http_getparam(req->body, HTTP_STR("password2"), &arena);

            if (!valid_name(name) || !valid_email(email) || !valid_pass(pass1)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid credentials
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            if (!http_streq(pass1, pass2)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        The password was repeated incorrectly
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            int ret = create_user(dbcache, name, email, pass1);
            if (ret < 0) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }
            user_id = ret;

            CSRFToken csrf_token;
            SessionToken sess_token;
            if (session_set_add(&sessions, user_id, &sess_token, &csrf_token) < 0) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            char cookie[1<<9];
            int cookie_len = snprintf(cookie, sizeof(cookie), "Set-Cookie: sess_id=%.*s; Path=/; HttpOnly", (int) sizeof(sess_token.data)-1, sess_token.data);
            if (cookie_len < 0 || cookie_len >= (int) sizeof(cookie)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            http_response_builder_status(builder, 200); // TODO: Whats the correct code here?
            http_response_builder_header(builder, (HTTP_String) { cookie, cookie_len });
            http_response_builder_header(builder, HTTP_STR("HX-Redirect: /index"));
            http_response_builder_body(builder, HTML_STR((
                <div class="success">
                    Welcome!
                </div>
            )));
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/api/logout"))) {

            if (user_id != -1)
                session_set_remove(&sessions, sess_token);

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

            if (!valid_post_title(title)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid title
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            if (!valid_link(link)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid link
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            if (!valid_post_content(content)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid content
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            bool is_link = false;
            if (link.len > 0) {
                is_link = true;
                content = link;
            }

            sqlite3_stmt *stmt;
            int ret = sqlite3utils_prepare_and_bind(dbcache, &stmt, "INSERT INTO Posts(author, title, is_link, content) VALUES (?, ?, ?, ?)", user_id, title, is_link, content);
            if (ret != SQLITE_OK) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            ret = sqlite3_step(stmt);
            if (ret != SQLITE_DONE) {
                sqlite3_reset(stmt);
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            int64_t tmp = sqlite3_last_insert_rowid(db);
            if (tmp < 0 || tmp > INT_MAX) {
                sqlite3_reset(stmt);
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }
            int post_id = (int) tmp;

            ret = sqlite3_reset(stmt);
            if (ret != SQLITE_OK) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            char location[1<<9];
            ret = snprintf(location, sizeof(location), "Location: /post?id=%d", post_id);
            if (ret < 0 || ret >= (int) sizeof(location)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            http_response_builder_status(builder, 303);
            http_response_builder_header(builder, (HTTP_String) { location, ret });
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/api/comment"))) {

            if (req->method != HTTP_METHOD_POST) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid request method
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            if (user_id == -1) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        You are not logged in
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            int         parent_post    = http_getparami(req->body, HTTP_STR("parent_post"),    &arena);
            int         parent_comment = http_getparami(req->body, HTTP_STR("parent_comment"), &arena);
            HTTP_String content        = http_getparam (req->body, HTTP_STR("content"),        &arena);

            content = http_trim(content);
            if (!valid_comment_content(content)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Invalid content
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            int ret;
            sqlite3_stmt *stmt;
            if (parent_comment == -1)
                ret = sqlite3utils_prepare_and_bind(dbcache, &stmt, "INSERT INTO Comments(author, content, parent_post) VALUES (?, ?, ?)", user_id, content, parent_post);
            else
                ret = sqlite3utils_prepare_and_bind(dbcache, &stmt, "INSERT INTO Comments(author, content, parent_post, parent_comment) VALUES (?, ?, ?, ?)", user_id, content, parent_post, parent_comment);
            if (ret != SQLITE_OK) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            ret = sqlite3_step(stmt);
            if (ret != SQLITE_DONE) {
                sqlite3_reset(stmt);
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            ret = sqlite3_reset(stmt);
            if (ret != SQLITE_OK) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            char location[1<<9];
            ret = snprintf(location, sizeof(location), "Location: /post?id=%d", parent_post);
            if (ret < 0 || ret >= (int) sizeof(location)) {
                http_response_builder_status(builder, 200);
                http_response_builder_body(builder, HTML_STR((
                    <div class="error">
                        Internal error
                    </div>
                )));
                http_response_builder_done(builder);
                continue;
            }

            http_response_builder_status(builder, 303);
            http_response_builder_header(builder, (HTTP_String) { location, ret });
            http_response_builder_done(builder);

        } else if (http_streq(path, HTTP_STR("/index"))) {

            template_eval(builder, 200, WL_STR("pages/index.wl"), tpcache, &arena, dbcache, user_id, -1);

        } else if (http_streq(path, HTTP_STR("/write"))) {

            if (user_id == -1) {
                // Not logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            template_eval(builder, 200, WL_STR("pages/write.wl"), tpcache, &arena, dbcache, user_id, -1);

        } else if (http_streq(path, HTTP_STR("/login"))) {

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            template_eval(builder, 200, WL_STR("pages/login.wl"), tpcache, &arena, dbcache, user_id, -1);

        } else if (http_streq(path, HTTP_STR("/signup"))) {

            if (user_id != -1) {
                // Already logged in
                http_response_builder_status(builder, 303);
                http_response_builder_header(builder, HTTP_STR("Location: /index"));
                http_response_builder_done(builder);
                continue;
            }

            template_eval(builder, 200, WL_STR("pages/signup.wl"), tpcache, &arena, dbcache, user_id, -1);

        } else if (http_streq(path, HTTP_STR("/post"))) {

            int post_id = http_getparami(req->url.query, HTTP_STR("id"), &arena);
            if (post_id < 0) {
                template_eval(builder, 404, WL_STR("pages/notfound.wl"), tpcache, &arena, dbcache, user_id, -1);
                continue;
            }

            sqlite3_stmt *stmt;
            int ret = sqlite3utils_prepare_and_bind(dbcache, &stmt, "SELECT COUNT(*) FROM Posts WHERE id=?", post_id);
            if (ret != SQLITE_OK) {
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }

            ret = sqlite3_step(stmt);
            if (ret != SQLITE_ROW) {
                sqlite3_reset(stmt);
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }
            int64_t num = sqlite3_column_int64(stmt, 0);

            ret = sqlite3_reset(stmt);
            if (ret != SQLITE_OK) {
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }

            if (num < 0) {
                http_response_builder_status(builder, 500);
                http_response_builder_done(builder);
                continue;
            }

            if (num == 0) {
                template_eval(builder, 404, WL_STR("pages/notfound.wl"), tpcache, &arena, dbcache, user_id, -1);
                continue;
            }

            template_eval(builder, 200, WL_STR("pages/post.wl"), tpcache, &arena, dbcache, user_id, post_id);

        } else {

            template_eval(builder, 404, WL_STR("pages/notfound.wl"), tpcache, &arena, dbcache, user_id, -1);
        }
    }

    sqlite_cache_free(dbcache);
    template_cache_free(tpcache);
    sqlite3_close(db);
    http_server_free(server);
    http_global_free();
    return 0;
}
