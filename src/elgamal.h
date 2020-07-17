#ifndef ELGAMAL_H
#define ELGAMAL_H

#define _GNU_SOURCE
#define BUCKET_NUM 65536
#define BUCKET_MAX 32

#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

#ifndef ERROR_PRINT
#define ERROR_PRINT 1
#endif
#ifndef INFO_PRINT
#define INFO_PRINT 1
#endif

#define error_print(...) \
  do { if (ERROR_PRINT) fprintf(stderr,  __VA_ARGS__); } while (0)

#define info_print(...) \
  do { if (INFO_PRINT) fprintf(stderr,  __VA_ARGS__); } while (0)

struct PrivateKey { unsigned char val[crypto_core_ristretto255_SCALARBYTES]; };
struct PublicKey { unsigned char val[crypto_core_ristretto255_BYTES]; };
struct CipherText {
  unsigned char c1[crypto_core_ristretto255_BYTES];
  unsigned char c2[crypto_core_ristretto255_BYTES]; 
};
struct SharedSecret {
  unsigned char val[crypto_core_ristretto255_BYTES];
};
struct PlainText {
  unsigned char val[crypto_core_ristretto255_BYTES];
};
struct UnrolledCipherText {
  struct CipherText arr[BUCKET_MAX];
};

int generate_key(struct PrivateKey *a);
int priv2pub(struct PublicKey *a, const struct PrivateKey priv);
int encrypt(struct CipherText *a, const struct PlainText plain, const struct PublicKey pub);
int decrypt(struct PlainText *a, const struct CipherText x, const struct PrivateKey key);
int shared_secret(struct SharedSecret *s, const struct CipherText x, const struct PrivateKey key);
int decrypt_with_sec(struct PlainText *a, const struct CipherText x, const struct SharedSecret s);
int encode(struct PlainText *a, const unsigned int message);
unsigned char decode(const struct PlainText x);
int decode_equal(const struct PlainText x, const unsigned int y);
int private_equality_test(struct CipherText *a, const struct CipherText x, const struct CipherText y);
int unroll(struct UnrolledCipherText *a, const unsigned char x, const struct PublicKey pub_key);
int reroll(unsigned char *a, const struct UnrolledCipherText uct, const struct PrivateKey priv_key);
int read_pubkey(struct PublicKey *a, const char *fn);
int write_pubkey(const struct PublicKey pubkey, const char *fn);
int read_privkey(struct PrivateKey *a, const char *fn);
int write_privkey(const struct PrivateKey privkey, const char *fn);

int add_ciphertext(struct CipherText *a, const struct CipherText x, const struct CipherText y);


int keygen_node(char *private_fn, char *public_fn);
int combine_public_keys(char *combined_fn, char **node_fns, const int ncount);
int combine_private_keys(char *combined_fn, char **node_fns, const int ncount);

int encrypt_file(char *key_fn, char *input_fn, char *output_fn);
int decrypt_file(char *key_fn, char *input_fn, char *output_fn);

int read_file_to_array(unsigned char *ans, char *fn, size_t max);
int read_binary_CipherText_file(unsigned char *ans, char *fn, int max_CipherText_num);
int encrypt_array(unsigned char *out, const unsigned char *in, const struct PublicKey pubkey, const unsigned int max_elem);
int decrypt_array(unsigned char *plain, const unsigned char *enc, const struct PrivateKey privkey, const unsigned int num_elem);

int add_all_ciphertexts(unsigned char *a1, const unsigned char *a2, const int num_ciphertexts);
int array_max_in_place(unsigned char *a1, const unsigned char *a2, const int num_array_elements);
int combine_binary_CipherText_files(char *combined_fn, char **fns, const int ncount);


#endif // ELGAMAL_H
