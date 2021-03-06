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

/* Convenience structs to make semantic usage more clear
 *
 * PrivateKey and PublicKey should be self-explanatory
 * CipherText is a single EC-ElGamal encrypted number
 * PlainText is a member of the Ristretto255 group
 *
 * SharedSecret gives one of the steps of ElGamal decryption, and they
 * can be used to do a distributed decryption of a CipherText
 *
 * UnrolledPlainText is an array of Ristretto255 group points, encoding
 * an integer in [0, ..., BUCKET_MAX] in a unary representation, so that
 * when ElGamal-encrypted, we can take max's by homomorphic encryption
 *
 * UnrolledCipherText is an array of CipherTexts, encoding an integer in
 * [0, ... , BUCKET_MAX] in a unary representation, so that we can
 * easily take max's of collections of CipherTexts by addition.
 *
 * */
struct PrivateKey { unsigned char val[crypto_core_ristretto255_SCALARBYTES]; };
struct PublicKey { unsigned char val[crypto_core_ristretto255_BYTES]; };
struct CipherText {
  unsigned char c1[crypto_core_ristretto255_BYTES];
  unsigned char c2[crypto_core_ristretto255_BYTES]; 
};
struct PlainText {
  unsigned char val[crypto_core_ristretto255_BYTES];
};
struct SharedSecret {
  unsigned char val[crypto_core_ristretto255_BYTES];
};
struct UnrolledCipherText {
  struct CipherText arr[BUCKET_MAX];
};
struct UnrolledPlainText {
  struct PlainText arr[BUCKET_MAX];
};
struct UnrolledSharedSecret {
  struct SharedSecret arr[BUCKET_MAX];
};

/* Most of the following functions store result in the first argument.
 *
 * Almost all of them furthermore return a negative value as an error code,
 * and will return 0 upon success. 
 *
 * Note however that a few will return a positive value corresponding
 * to length on success. These functions will be separately noted.
 *
 * */

/* generates a random scalar in Ristretto255 as a private elgamal key */
int generate_key(struct PrivateKey *a);

/* generates a public elgamal key from a private key by taking g*priv.val */
int priv2pub(struct PublicKey *a, const struct PrivateKey priv);

/* encryption and decryption via public/private keys respectively */
int encrypt(struct CipherText *a, const struct PlainText plain, const struct PublicKey pub);
int decrypt(struct PlainText *a, const struct CipherText x, const struct PrivateKey key);

/* The basic homomorphic binary operation */
int add_ciphertext(struct CipherText *a, const struct CipherText x, const struct CipherText y);

/* generate a shared secret for distributed decryption of CipherText */
int shared_secret(struct SharedSecret *s, const struct CipherText x, const struct PrivateKey key);
int decrypt_with_sec(struct PlainText *a, const struct CipherText x, const struct SharedSecret s);

/* encoding / decoding integers as Ristretto255 elements 
 *
 * encode is self-explanatory
 * decode can only return values in [0, 255]. This is a design choice as
 *   division in the group can be expensive, as we perform a linear loop
 *   over all possibilities
 * decode_equal tests whether or not the decoded value is a particular
 * integer, and is much faster than "decode"
 *
 * */
int encode(struct PlainText *a, const unsigned int message);
unsigned char decode(const struct PlainText x);
int decode_equal(const struct PlainText x, const unsigned int y);

/* Performs a private equality test that gives a CipherText 0 if x == y,
 * and a random number otherwise */
int private_equality_test(struct CipherText *a, const struct CipherText x, const struct CipherText y);

/* Encodes/decodes a character in [0, BUCKET_MAX] to/from unary */
int unroll(struct UnrolledPlainText *a, const unsigned char x);
int reroll(unsigned char *a, const struct UnrolledPlainText upt);
int unroll_and_encrypt(struct UnrolledCipherText *a, const unsigned char x, const struct PublicKey pub_key);
int decrypt_and_reroll(unsigned char *a, const struct UnrolledCipherText uct, const struct PrivateKey priv_key);
int decrypt_and_reroll_with_sec(unsigned char *a, const struct UnrolledCipherText uct, const struct UnrolledSharedSecret uss);

/* File IO functions */
int read_pubkey(struct PublicKey *a, const char *fn);
int write_pubkey(const struct PublicKey pubkey, const char *fn);
int read_privkey(struct PrivateKey *a, const char *fn);
int write_privkey(const struct PrivateKey privkey, const char *fn);

/* File IO wrapper
 * keygen_node will ensure that a private key is stored in private_fn and 
 * a matching public key is stored in public_fn, generating them if necessary,
 * though it will try not to clobber existing files and will emit an error if 
 * those files are not actually a public/private key pair */
int keygen_node(char *private_fn, char *public_fn);

/* combines files containing either public or private keys into a single one
 * for distributed computations */
int combine_public_keys(char *combined_fn, char **node_fns, const int ncount);
int combine_private_keys(char *combined_fn, char **node_fns, const int ncount);

// Encrypts a newline delimited list of integers in [0,BUCKET_MAX] from input_fn and writes it out to output_fn, using the public key found in key_fn
int encrypt_bucket_file(char *key_fn, char *input_fn, char *output_fn);
// Reverses the encryption from encrypt_bucket_file
int decrypt_bucket_file(char *key_fn, char *input_fn, char *output_fn);
// Reverses the encryption from encrypt_bucket_file
int decrypt_bucket_file_with_sec(char *shared_sec_fn, char *input_fn, char *output_fn);
// Reads newline separated integers in [0,BUCKET_MAX] file into array. If items were read, return the number. Return a negative number upon error.
// max is the size of the ans buffer
int read_file_to_array(unsigned char *ans, char *fn, size_t buf_size);
// Reads binary encrypted file into array, with serialized CipherText objects. Returns the number of objects read. Returns a negative number on error.
// sizeof ans = buf_size in bytes
int read_binary_CipherText_file(unsigned char *ans, char *fn, int buf_size);
// Gets the shared secrets for a partial decryption of a file
int get_partial_decryptions(char *key_fn, char *input_fn, char *output_fn);
// decrypts a file with a collection of partial decryptions
int combine_partial_decryptions(char *combined_fn, char **node_fns, const int ncount);
// Reads binary shared secrets file into array, with serialized SharedSecrets objects. Returns the number of objects read. Returns a negative number on error.
// sizeof ans = buf_size in bytes
int read_partial_decryption_file(unsigned char *ans, char *fn, int buf_size);

// Returns the number of buckets in UnrolledCipherTexts
// Returns negative value on error 
// array "in" should be (-1)-delimited (alternately 255-delimited)
// max_elem is in units of UnrolledCipherTexts
int encrypt_buckets(unsigned char *out, const unsigned char *in, const struct PublicKey pubkey, const unsigned int max_buckets);
// Decrypt array
// Returns the number of buckets on success
// Returns negative value on error
// plain must have space for num_buckets + 1 (to null terminate)
int decrypt_buckets(unsigned char *plain, const unsigned char *enc, const struct PrivateKey privkey, const unsigned int num_buckets);
int decrypt_buckets_with_sec(unsigned char *plain, const unsigned char *enc, const unsigned char *shared_sec, const unsigned int num_buckets);

// a1 and a2 are byte arrays of concatenated CipherTexts
int add_all_ciphertexts(unsigned char *a1, const unsigned char *a2, const int num_ciphertexts);
// a1 and a2 are byte arrays of concatenated SharedSecrets
int add_all_secrets(unsigned char *a1, const unsigned char *a2, const int num_ciphertexts);
// a1 and a2 are byte arrays of concatenated UnrolledCipherTexts
//int array_max_in_place(unsigned char *a1, const unsigned char *a2, const int num_array_elements);
// Adds together all ciphertexts found in fns, and puts output in combined_fn
// ncount = number of CipherTexts
int combine_binary_CipherText_files(char *combined_fn, char **fns, const int ncount);



#endif // ELGAMAL_H
