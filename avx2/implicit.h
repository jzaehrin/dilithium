#ifndef IMPLICIT_H
#define IMPLICIT_H

/* Implicit functions to avoid warning during the compilation */

int pqcrystals_dilithium1_avx2_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int pqcrystals_dilithium1_avx2_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *msg, unsigned long long len, const unsigned char *sk);
int pqcrystals_dilithium1_avx2_crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

int pqcrystals_dilithium2_avx2_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int pqcrystals_dilithium2_avx2_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *msg, unsigned long long len, const unsigned char *sk);
int pqcrystals_dilithium2_avx2_crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

int pqcrystals_dilithium3_avx2_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int pqcrystals_dilithium3_avx2_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *msg, unsigned long long len, const unsigned char *sk);
int pqcrystals_dilithium3_avx2_crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

int pqcrystals_dilithium4_avx2_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int pqcrystals_dilithium4_avx2_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *msg, unsigned long long len, const unsigned char *sk);
int pqcrystals_dilithium4_avx2_crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

#endif