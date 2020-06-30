#ifndef GENERIC_API_H
#define GENERIC_API_H

#include <stdint.h>
#include <stdbool.h>

struct dilithium {
    int type;
    unsigned char * pk;
    unsigned char * sk;
};
typedef struct dilithium DILITHIUM;

/* Security level */
#define DILITHIUM4 4
#define DILITHIUM3 3
#define DILITHIUM2 2
#define DILITHIUM1 1

DILITHIUM *dilithium_new(void);
int dilithium_prepare(DILITHIUM* d, int type);
int dilithium_generate_key(DILITHIUM* d);
int dilithium_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *msg, unsigned long long len, const DILITHIUM* d);
int dilithium_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const DILITHIUM* d);
void dilithium_free(DILITHIUM* d);

bool dilithium_is_valid_type(int type);
size_t dilithium_sk_bytes(DILITHIUM * d);
size_t dilithium_pk_bytes(DILITHIUM * d);
size_t dilithium_sign_bytes(DILITHIUM * d, size_t data_len);

#endif