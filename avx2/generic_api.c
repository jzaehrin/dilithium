#include <stdlib.h>
#include <stdbool.h>

#include "generic_api.h"
#include "implicit.h"
#include "config.h"

/* Allocate Dilithium structure */
DILITHIUM *dilithium_new(void) {
    DILITHIUM * dilithium = NULL;

    if ((dilithium = malloc(sizeof(DILITHIUM))) == NULL) {
        return NULL; /* Allocation error */
    }

    dilithium->pk = NULL;
    dilithium->sk = NULL;
    dilithium->type = -1;

    return dilithium;
}

/* Prepare key buffers according to dilithium variant type to store them */
int dilithium_prepare(DILITHIUM* d, int type) {
    if (!dilithium_is_valid_type(type))
        return 1; /* Type unknown */

    d->type = type;

    if ((d->pk = malloc(dilithium_pk_bytes(d))) == NULL ||
	    (d->sk = malloc(dilithium_sk_bytes(d))) == NULL) {
		return 1; /* Allocation error */
	}

    return 0;
}

/* Verify if the variant type is a correct type for dilithium */
bool dilithium_is_valid_type(int type) {
    switch (type)
    {
        case DILITHIUM1:
        case DILITHIUM2:
        case DILITHIUM3:
        case DILITHIUM4:
            return true;
        default: 
            return false;
    }
}

/* Get the secret key size */
size_t dilithium_sk_bytes(DILITHIUM * d) {
    size_t size = 0;
    switch (d->type)
    {
        case DILITHIUM1:
            size = 2096; 
            break;

        case DILITHIUM2:
            size = 2800;
            break;

        case DILITHIUM3:
            size = 3504;
            break;

        case DILITHIUM4:
            size = 3856;
            break;
    }

    return size;
}

/* Get the public key size */
size_t dilithium_pk_bytes(DILITHIUM * d) {
    size_t size = 0;
    
    switch (d->type)
    {
        case DILITHIUM1:
            size = 896; 
            break;

        case DILITHIUM2:
            size = 1184;
            break;

        case DILITHIUM3:
            size = 1472;
            break;

        case DILITHIUM4:
            size = 1760;
            break;
    }

    return size;
}

/* Get the signature size according to the size of data need to be sign */
size_t dilithium_sign_bytes(DILITHIUM * d, size_t data_len) {
    size_t size = 0;
    
    switch (d->type)
    {
        case DILITHIUM1:
            size = 1387; 
            break;

        case DILITHIUM2:
            size = 2044;
            break;

        case DILITHIUM3:
            size = 2701;
            break;

        case DILITHIUM4:
            size = 3366;
            break;
    }

    return size + data_len;
}

/* Generate a pair of secret and public keys */
int dilithium_generate_key(DILITHIUM* d) {
    switch (d->type)
    {
        case DILITHIUM1:
            return pqcrystals_dilithium1_avx2_crypto_sign_keypair(d->pk, d->sk);

        case DILITHIUM2:
            return pqcrystals_dilithium2_avx2_crypto_sign_keypair(d->pk, d->sk);

        case DILITHIUM3:
            return pqcrystals_dilithium3_avx2_crypto_sign_keypair(d->pk, d->sk);

        case DILITHIUM4:
            return pqcrystals_dilithium4_avx2_crypto_sign_keypair(d->pk, d->sk);
    }

    return 1;
}

/* Sign msg inside sm, the user need to allocate the output buffer */
int dilithium_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *msg, unsigned long long len, const DILITHIUM* d) {
    switch (d->type)
    {
        case DILITHIUM1:
            return pqcrystals_dilithium1_avx2_crypto_sign(sm, smlen, msg, len, d->sk);

        case DILITHIUM2:
            return pqcrystals_dilithium2_avx2_crypto_sign(sm, smlen, msg, len, d->sk);

        case DILITHIUM3:
            return pqcrystals_dilithium3_avx2_crypto_sign(sm, smlen, msg, len, d->sk);

        case DILITHIUM4:
            return pqcrystals_dilithium4_avx2_crypto_sign(sm, smlen, msg, len, d->sk);
    }

    return 1;
}

/* Verify and open signature inside m, the user need to allocate the output buffer */
int dilithium_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const DILITHIUM* d){
    switch (d->type)
    {
        case DILITHIUM1:
            return pqcrystals_dilithium1_avx2_crypto_sign_open(m, mlen, sm, smlen, d->pk);

        case DILITHIUM2:
            return pqcrystals_dilithium2_avx2_crypto_sign_open(m, mlen, sm, smlen, d->pk);

        case DILITHIUM3:
            return pqcrystals_dilithium3_avx2_crypto_sign_open(m, mlen, sm, smlen, d->pk);

        case DILITHIUM4:
            return pqcrystals_dilithium4_avx2_crypto_sign_open(m, mlen, sm, smlen, d->pk);
    }

    return 1;
}

/* Free dilithium structure */
void dilithium_free(DILITHIUM* d) {
    if (d == NULL)
        return;

    if(d->pk != NULL)
        free(d->pk);

    if(d->sk != NULL)
        free(d->sk);

    free(d);
}
