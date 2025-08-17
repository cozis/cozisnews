#include <stddef.h>
#include <string.h>
#include <crypt_blowfish.h>
#include "bcrypt.h"
#include "random.h"

int hash_password(char *pass, int passlen, int cost, PasswordHash *hash)
{
    char passzt[128];
    if (passlen >= (int) sizeof(passzt))
        return -1;
    memcpy(passzt, pass, passlen);
    passzt[passlen] = '\0';

    char random[16];
    int ret = generate_random_bytes(random, (int) sizeof(random));
    if (ret) return -1;

    char salt[30];
    if (_crypt_gensalt_blowfish_rn("$2b$", cost, random, sizeof(random), salt, sizeof(salt)) == NULL)
        return -1;

    if (_crypt_blowfish_rn(passzt, salt, hash->data, (int) sizeof(hash->data)) == NULL)
        return -1;

    return 0;
}

int check_password(char *pass, int passlen, PasswordHash hash)
{
    char passzt[128];
    if (passlen >= (int) sizeof(passzt))
        return -1;
    memcpy(passzt, pass, passlen);
    passzt[passlen] = '\0';

    PasswordHash new_hash;
    if (_crypt_blowfish_rn(passzt, hash.data, new_hash.data, sizeof(new_hash.data)) == NULL)
        return -1;

    if (strcmp(hash.data, new_hash.data)) // TODO: should be constant-time
        return 1;

    return 0;
}
