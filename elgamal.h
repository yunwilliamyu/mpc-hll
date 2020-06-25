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
int generate_key(struct PrivateKey *a);
int priv2pub(struct PublicKey *a, const struct PrivateKey priv);
int encrypt(struct CipherText *a, const struct PlainText plain, const struct PublicKey pub);
int decrypt(struct PlainText *a, const struct CipherText x, const struct PrivateKey key);

/* generates a random scalar as a private elgamal key */
int generate_key(struct PrivateKey *a) {
  crypto_core_ristretto255_scalar_random(a->val);
  return 0;
}

/* generates a public elgamal key from a private key by taking g^priv.val */
int priv2pub(struct PublicKey *a, const struct PrivateKey priv) {
  if (crypto_scalarmult_ristretto255_base(a->val, priv.val) != 0) {
    return -1;
  }
  return 0;
}

/* performs elgamal encryption */
int encrypt(struct CipherText *a, const struct PlainText plain, const struct PublicKey pub) {
  unsigned char y[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(y);
  unsigned char s[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(s, y, pub.val) != 0) {
    return -1;
  }
  crypto_scalarmult_ristretto255_base(a->c1, y);
  if (crypto_core_ristretto255_add(a->c2, plain.val, s) != 0) {
    return -1;
  }
  return 0;
}

/* decrypts elgamal encryption */
int decrypt(struct PlainText *a, const struct CipherText x, const struct PrivateKey key) {
  unsigned char s[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(s, key.val, x.c1) != 0) {
    return -1;
  }
  if (crypto_core_ristretto255_sub(a->val, x.c2, s) != 0) {
    return -1;
  }
  return 0;
}

/* encodes a single byte as a PlainText Ristretto point message */
int encode(struct PlainText *a, const unsigned char message) {
  unsigned char s[crypto_core_ristretto255_SCALARBYTES];
  memset(s, 0, sizeof s);
  s[0] = message;
  return crypto_scalarmult_ristretto255_base(a->val, s); // will return 0 on success and -1 on failure
}

/* add ciphertexts */
int add_ciphertext(struct CipherText *a, const struct CipherText x, const struct CipherText y) {
  if (crypto_core_ristretto255_add(a->c1, x.c1, y.c1) != 0) {
    return -1;
  }
  if (crypto_core_ristretto255_add(a->c2, x.c2, y.c2) != 0) {
    return -1;
  }
  return 0;
}


// decodes a Ristretto point message to a byte with value 1 to 255 inclusive.
// returns 0 on failure (i.e. not in range [1,255])
// returns value if within that range
unsigned char decode(const struct PlainText x) {
  unsigned char a = 0;
  unsigned char s[crypto_core_ristretto255_SCALARBYTES];
  struct PlainText guess;
  memset(s, 0, sizeof s);
  for (int i=1; i<256; i++) {
    s[0]=i;
    crypto_scalarmult_ristretto255_base(guess.val, s);
    if (memcmp(guess.val, x.val, crypto_core_ristretto255_BYTES)==0) {
      a = i % 256;
      return a;
    }
  }
  return a;
}




#endif
