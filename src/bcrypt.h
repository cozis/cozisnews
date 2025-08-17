#ifndef BCRYPT_INCLUDED
#define BCRYPT_INCLUDED

typedef struct {
    char data[61];
} PasswordHash;

int hash_password(char *pass, int passlen, int cost, PasswordHash *hash);
int check_password(char *pass, int passlen, PasswordHash hash);

#endif // BCRYPT_INCLUDED
