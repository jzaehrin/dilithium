#include <stdlib.h>
#include "generic_api.h"
#include "config.h"

DILITHIUM * dilithium_new(int security_level) {
    DILITHIUM * dilithium = NULL;

    if ((dilithium = malloc(sizeof(DILITHIUM))) == NULL) {
        return NULL; /* Allocation error */
    }

    dilithium->security_level = security_level;

    if ((dilithium->pk = malloc(dilithium_pk_bytes(dilithium))) == NULL ||
	    (dilithium->sk = malloc(dilithium_sk_bytes(dilithium))) == NULL) {
        free(dilithium);
		return NULL;
	}

    return dilithium;
}

size_t dilithium_sk_bytes(DILITHIUM * d) {
    size_t size = 0;
    switch (d->security_level)
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

size_t dilithium_pk_bytes(DILITHIUM * d) {
    size_t size = 0;
    switch (d->security_level)
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

int dilithium_generate_key(DILITHIUM* d) {
    switch (d->security_level)
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

int dilithium_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *msg, unsigned long long len, const DILITHIUM* d) {
    switch (d->security_level)
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
int dilithium_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const DILITHIUM* d){
    switch (d->security_level)
    {
        case DILITHIUM1:
            return pqcrystals_dilithium1_avx2_crypto_sign_keypair(m, mlen, sm, smlen, d->pk);

        case DILITHIUM2:
            return pqcrystals_dilithium2_avx2_crypto_sign_keypair(m, mlen, sm, smlen, d->pk);

        case DILITHIUM3:
            return pqcrystals_dilithium3_avx2_crypto_sign_keypair(m, mlen, sm, smlen, d->pk);

        case DILITHIUM4:
            return pqcrystals_dilithium4_avx2_crypto_sign_keypair(m, mlen, sm, smlen, d->pk);
    }

    return 1;
}
