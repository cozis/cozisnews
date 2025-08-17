#include <stddef.h>
#include <string.h>
#include <crypt_blowfish.h>
#include "bcrypt.h"

int hash_password(char *pass, int passlen, int cost, PasswordHash *hash)
{
    char passzt[128];
    if (passlen >= (int) sizeof(passzt))
        return -1;
    memcpy(passzt, pass, passlen);
    passzt[passlen] = '\0';

    unsigned char random[16] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // TODO
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };

    char salt[30];
    if (_crypt_gensalt_blowfish_rn("$2b$", cost, (char*) random, sizeof(random), salt, sizeof(salt)) == NULL)
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
