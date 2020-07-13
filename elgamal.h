#ifndef ELGAMAL_H
#define ELGAMAL_H

//#include <stdio.h>
#include <sodium.h>
#include <inttypes.h>
#include <string.h>

struct PrivateKey { unsigned char val[crypto_core_ristretto255_SCALARBYTES]; };
struct PublicKey { unsigned char val[crypto_core_ristretto255_BYTES]; };
struct CipherText {
  unsigned char c1[crypto_core_ristretto255_BYTES];
  unsigned char c2[crypto_core_ristretto255_BYTES]; 
};
struct PlainText {
  unsigned char val[crypto_core_ristretto255_BYTES];
};
struct UnrolledCipherText64 {
  struct CipherText arr[64];
};

int generate_key(struct PrivateKey *a);
int priv2pub(struct PublicKey *a, const struct PrivateKey priv);
int encrypt(struct CipherText *a, const struct PlainText plain, const struct PublicKey pub);
int decrypt(struct PlainText *a, const struct CipherText x, const struct PrivateKey key);
int encode(struct PlainText *a, const unsigned int message);
int decode_equal(const struct PlainText x, const unsigned int y);
int private_equality_test(struct CipherText *a, const struct CipherText x, const struct CipherText y);
int unroll(struct UnrolledCipherText64 *a, const unsigned char x, const struct PublicKey pub_key);
int reroll(unsigned char *a, const struct UnrolledCipherText64 uct, const struct PrivateKey priv_key);
int read_pubkey(struct PublicKey *a, const char *fn);
int write_pubkey(const struct PublicKey pubkey, const char *fn);
int read_privkey(struct PrivateKey *a, const char *fn);
int write_privkey(const struct PrivateKey privkey, const char *fn);




#endif // ELGAMAL_H
