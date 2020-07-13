// ELGAMAL.C
#include "elgamal.h"

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

/* encodes an unsigned int as a PlainText Ristretto point message
 *
 * Will return -1 if message=0, or 0 otherwise.
 * */
int encode(struct PlainText *a, const unsigned int message) {
  unsigned char s[crypto_core_ristretto255_SCALARBYTES];
  memset(s, 0, sizeof s);
  //s[0] = message;
  memcpy(s,(char*)&message, sizeof(unsigned int));
  return crypto_scalarmult_ristretto255_base(a->val, s);
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

/* tests if a Ristretto point message decrypts to a particular integer
 * returns -1 on failure (i.e. not equal)
 * returns 0 on success (i.e. equal)
 * */
int decode_equal(const struct PlainText x, const unsigned int y) {
  unsigned char s[crypto_core_ristretto255_SCALARBYTES];
  struct PlainText guess;
  memset(s, 0, sizeof s);
  memcpy(s,(char*)&y, sizeof(unsigned int));
  crypto_scalarmult_ristretto255_base(guess.val, s);
  if (memcmp(guess.val, x.val, crypto_core_ristretto255_BYTES)==0) {
    return 0;
  }
  return -1;
}

/* Puts an enciphered 0 into "a" if the two are equal. Otherwise "a" is an enciphered random number
 *
 * returns 0 on success, and -1 on failure
 *
 * https://crypto.stackexchange.com/questions/9527/how-does-an-oblivious-test-of-plaintext-equality-work
*/
int private_equality_test(struct CipherText *a, const struct CipherText x, const struct CipherText y) {
  // t.c1 = x.c1 - y.c1
  // t.c2 = x.c2 - y.c2
  // z = randint(0, L)
  // a->c1 = t.c1 * z
  // a->c2 = t.c2 * z
  struct CipherText t;
  if (crypto_core_ristretto255_sub(t.c1, x.c1, y.c1) != 0) {return -1; }
  if (crypto_core_ristretto255_sub(t.c2, x.c2, y.c2) != 0) {return -1; }
  unsigned char z[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(z);
  if (crypto_scalarmult_ristretto255(a->c1, z, t.c1) != 0) {return -1; }
  if (crypto_scalarmult_ristretto255(a->c2, z, t.c2) != 0) {return -1; }
  return 0;
}

/* Unrolls an int x=4 into an encrypted array [r, r, r, r, 0, 0, ..., 0], where
 *   each r is a random value
 *   x is the number of r's
 *   the length of the array = 64
 *
 * Puts the result into "a", and returns 0 on success, -1 on failure
 * */
int unroll(struct UnrolledCipherText64 *a, const unsigned char x, const struct PublicKey pub_key) {
  struct PlainText tmp_plain;
  // Can only encode values from 1 to 64
  if (x > 64) {return -1; }
  if (x == 0 ) { return -1; }
  for (int i=0; i<x; i++) {
    crypto_core_ristretto255_random(tmp_plain.val);
    if (encrypt( &(a->arr[i]), tmp_plain, pub_key) != 0) {return -1; }
  }
  for (int i=x; i<64; i++) {
    if (encode(&tmp_plain, 0) != -1) {return -1; }
    if (encrypt( &(a->arr[i]), tmp_plain, pub_key) != 0) {return -1; }
  }
  return 0;
}

/* Rerolls and decrypts an UnrolledCipherText64 back into an integer from 1 to 64 */
int reroll(unsigned char *a, const struct UnrolledCipherText64 uct, const struct PrivateKey priv_key) {
  struct PlainText tmp_plain;
  for (int i=0; i<64; i++) {
    if (decrypt(&tmp_plain, uct.arr[i], priv_key)!=0) {return -1;}
    if (decode_equal(tmp_plain, 0)==0) {
      *a = i;
      return 0;
    }
  }
  *a = 64;
  return 0;
}

/* Tests if Public Key file exists already, is a public key, and if so,
 * reads the file into struct
 *
 * We are deliberately very strict and will return an error if anything
 * seems wrong.
 *
 * We will return 0 on success and a nonzero value on failure
 * */
int read_pubkey(struct PublicKey *a, const char *fn) {
  unsigned char buffer[crypto_core_ristretto255_SCALARBYTES + 1];
  FILE *pubkey_file = fopen(fn, "rb");
  size_t bytes_read = 0;
  if (pubkey_file) {
    bytes_read = fread(buffer, 1, crypto_core_ristretto255_BYTES + 1, pubkey_file);
    if ((bytes_read != crypto_core_ristretto255_BYTES) ||
        (crypto_core_ristretto255_is_valid_point(buffer)==0)){
      printf("ERROR: %s exists and is not a public key file.\n", fn);
      return -2;
    } else {
      printf("INFO: Using %s as public key.\n", fn);
      memcpy(a->val, buffer, crypto_core_ristretto255_BYTES);
      return 0;
    }
    fclose(pubkey_file);
  }
  return -1;
}

/* Writes Public Key out to a file from a struct.
 */
int write_pubkey(const struct PublicKey pubkey, const char *fn) {
  size_t bytes_written = 0;
  FILE *key_file = fopen(fn, "wb");
  if (key_file) {
    bytes_written = fwrite(pubkey.val, 1, crypto_core_ristretto255_BYTES, key_file);
    if (bytes_written != crypto_core_ristretto255_BYTES) {
        printf("ERROR: incorrect number of bytes written to %s.\n", fn);
        return -5;
    }
    printf("INFO: writing public key to %s.\n", fn);
    fclose(key_file);
    return 0;
  } else {
    printf("ERROR: could not open %s for writing.\n", fn);
    return -6;
  }
}

/* Tests if Private Key file exists already, is a private key, and if so,
 * reads the file into struct
 *
 * We are deliberately very strict and will return an error if anything
 * seems wrong.
 *
 * We will return 0 on success and a nonzero value on failure
 * */
int read_privkey(struct PrivateKey *a, const char *fn) {
  unsigned char buffer[crypto_core_ristretto255_SCALARBYTES + 1];
  FILE *privkey_file = fopen(fn, "rb");
  size_t bytes_read = 0;
  if (privkey_file) {
    bytes_read = fread(buffer, 1, crypto_core_ristretto255_SCALARBYTES + 1, privkey_file);
    if (bytes_read != crypto_core_ristretto255_SCALARBYTES){
      printf("ERROR: %s exists and is not a private key file.\n", fn);
      return -2;
    } else {
      printf("INFO: Using %s as private key.\n", fn);
      memcpy(a->val, buffer, crypto_core_ristretto255_SCALARBYTES);
      return 0;
    }
    fclose(privkey_file);
  }
  return -1;
}

/* Writes Private Key out to a file from a struct.
 */
int write_privkey(const struct PrivateKey privkey, const char *fn) {
  size_t bytes_written = 0;
  FILE *key_file = fopen(fn, "wb");
  if (key_file) {
    bytes_written = fwrite(privkey.val, 1, crypto_core_ristretto255_SCALARBYTES, key_file);
    if (bytes_written != crypto_core_ristretto255_SCALARBYTES) {
        printf("ERROR: incorrect number of bytes written to %s.\n", fn);
        return -5;
    }
    printf("INFO: writing private key to %s.\n", fn);
    fclose(key_file);
    return 0;
  } else {
    printf("ERROR: could not open %s for writing.\n", fn);
    return -6;
  }
}
