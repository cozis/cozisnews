#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "random.h"
#include "session.h"

#define CSRF_RAW_TOKEN_SIZE 32
#define SESS_RAW_TOKEN_SIZE 32

#define CSRF_TOKEN_SIZE (2 * CSRF_RAW_TOKEN_SIZE)
#define SESS_TOKEN_SIZE (2 * SESS_RAW_TOKEN_SIZE)

typedef struct {
    int  user;
    char csrf[CSRF_TOKEN_SIZE];
    char sess[SESS_TOKEN_SIZE];
} Session;

struct SessionStorage {
    int count;
    int capacity;
    Session items[];
};

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

static void unpack_token(char *src, int srclen, char *dst, int dstlen)
{
    assert(2 * srclen == dstlen);

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

    assert(srclen == 2 * dstlen);

    for (int i = 0; i < srclen; i += 2) {
        int high = src[i+0];
        int low  = src[i+1];
        if (!is_hex_digit(high) || !is_hex_digit(low))
            return -1;
        dst[i] = (hex_digit_to_int(high) << 4) | (hex_digit_to_int(low) << 0);
    }

    return 0;
}

SessionStorage *session_storage_init(int max_sessions)
{
    int capacity = 2 * max_sessions;
    SessionStorage *storage = malloc(sizeof(SessionStorage) + capacity * sizeof(Session));
    if (storage == NULL)
        return NULL;
    storage->count = 0;
    storage->capacity = capacity;
    for (int i = 0; i < capacity; i++)
        storage->items[i].user = -1;
    return storage;
}

void session_storage_free(SessionStorage *storage)
{
    free(storage);
}

static Session *lookup_session_slot(SessionStorage *storage, HTTP_String sess, bool find_unused)
{
    if (find_unused && 2 * storage->count + 2 > storage->capacity)
        return NULL;

    if (sess.len != SESS_TOKEN_SIZE)
        return NULL;

    uint64_t key;
    if (sess.len < (int) (2 * sizeof(key)))
        return NULL;
    for (int i = 0; i < (int) sizeof(key); i++) {

        int high = sess.ptr[(i << 1) | 0];
        int low  = sess.ptr[(i << 1) | 1];

        if (!is_hex_digit(sess.ptr[i+0]) ||
            !is_hex_digit(sess.ptr[i+1]))
            return NULL;

        key <<= 4;
        key |= hex_digit_to_int(high);

        key <<= 4;
        key |= hex_digit_to_int(low);
    }
    int i = key % storage->capacity;

    for (int j = 0; j < storage->capacity; j++) {

        if (find_unused) {

            if (storage->items[i].user < 0)
                return &storage->items[i]; // Unused slot

        } else {

            if (storage->items[i].user == -1)
                return NULL;

            if (storage->items[i].user != -2)
                if (!memcmp(storage->items[i].sess, sess.ptr, SESS_TOKEN_SIZE))
                    return &storage->items[i];
        }

        i++;
        if (i == storage->capacity)
            i = 0;
    }

    return NULL;
}

int create_session(SessionStorage *storage, int user, HTTP_String *psess, HTTP_String *pcsrf)
{
    int ret;
    char raw_sess[SESS_RAW_TOKEN_SIZE];
    char raw_csrf[CSRF_RAW_TOKEN_SIZE];

    ret = generate_random_bytes(raw_sess, SESS_RAW_TOKEN_SIZE);
    if (ret) return -1;

    ret = generate_random_bytes(raw_csrf, CSRF_RAW_TOKEN_SIZE);
    if (ret) return -1;

    char sess[SESS_TOKEN_SIZE];
    char csrf[CSRF_TOKEN_SIZE];
    unpack_token(raw_sess, SESS_RAW_TOKEN_SIZE, sess, SESS_TOKEN_SIZE);
    unpack_token(raw_csrf, CSRF_RAW_TOKEN_SIZE, csrf, CSRF_TOKEN_SIZE);

    Session *found = lookup_session_slot(storage, (HTTP_String) { sess, SESS_TOKEN_SIZE }, true);
    if (found == NULL) return -1;

    found->user = user;
    memcpy(found->sess, sess, SESS_TOKEN_SIZE);
    memcpy(found->csrf, csrf, CSRF_TOKEN_SIZE);

    *psess = (HTTP_String) { found->sess, SESS_TOKEN_SIZE };
    *pcsrf = (HTTP_String) { found->csrf, CSRF_TOKEN_SIZE };

    storage->count++;
    return 0;
}

int delete_session(SessionStorage *storage, HTTP_String sess)
{
    char raw_sess[SESS_RAW_TOKEN_SIZE];
    if (sess.len != SESS_TOKEN_SIZE || pack_token(sess.ptr, sess.len, raw_sess, (int) sizeof(raw_sess)) < 0)
        return -1;
    Session *found = lookup_session_slot(storage, sess, false);
    if (found == NULL)
        return false;
    assert(found->user >= 0);
    found->user = -2;
    storage->count--;
    return 0;
}

int find_session(SessionStorage *storage, HTTP_String sess, HTTP_String *pcsrf, int *puser)
{
    Session *found = lookup_session_slot(storage, sess, false);
    if (found == NULL)
        return -1;
    assert(found->user >= 0);
    *pcsrf = (HTTP_String) { found->csrf, CSRF_TOKEN_SIZE };
    *puser = found->user;
    return 0;
}
