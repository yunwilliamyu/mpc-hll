// keygen-node.c
#include <stdio.h>
#include <stdbool.h>
#include "elgamal.h"

int main( int argc, char *argv[] ) {
  if (argc < 3) {
    printf(
      "Usage:\n"
      "  %s combined.key [node1.key node2.key ... nodeN.key]\n\n"
      "Generates a combined public key by adding together a\n"
      "list of node public keys.\n"
      , argv[0]);
    return 1;
  }
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  // Make sure we don't clobber an existing file
  FILE *combined_key_file = fopen(argv[1], "rb");
  if (combined_key_file) {
    printf("ERROR: %s exists.\nAborting so we don't clobber it.\n", argv[1]);
    fclose(combined_key_file);
    return -2;
  }

  FILE *node_key_file;
  unsigned char buffer[crypto_core_ristretto255_BYTES + 1];
  size_t bytes_read = 0;
  struct PublicKey combkey;
  memset(combkey.val, 0, sizeof combkey.val);
  struct PublicKey tempkey;
  memset(tempkey.val, 0, sizeof tempkey.val);
  // Add together all of the node keys as points on Ristretto255
  for (int file_it=2; file_it<argc; file_it++) {
    node_key_file = fopen(argv[file_it], "rb");
    if (node_key_file) {
      printf("INFO: Reading %s as public key file.\n", argv[file_it]);
      bytes_read = fread(buffer, 1, crypto_core_ristretto255_BYTES + 1, node_key_file);
      if ((bytes_read != crypto_core_ristretto255_BYTES) ||
          (crypto_core_ristretto255_is_valid_point(buffer)==0)){
        printf("ERROR: %s is not a public key file.\nAborting\n", argv[file_it]);
        return -3;
      }
      if (crypto_core_ristretto255_add(combkey.val, tempkey.val, buffer)!=0) {
        printf("ERROR: problem adding %s to combined key.\nAborting\n", argv[file_it]);
        return -4;
      }
      memcpy(tempkey.val, combkey.val, crypto_core_ristretto255_BYTES);
      fclose(node_key_file);
    } else {
      printf("ERROR: could not open %s for reading.\n", argv[file_it]);
      return -10;
    }
  }

  // generate combined public key now
  size_t bytes_written = 0;
  combined_key_file = fopen(argv[1], "wb");
  if (combined_key_file) {
    bytes_written = fwrite(combkey.val, 1, crypto_core_ristretto255_BYTES, combined_key_file);
    if (bytes_written != crypto_core_ristretto255_BYTES) {
        printf("ERROR: incorrect number of bytes written to %s.\nAborting\n", argv[1]);
        return -5;
    }
    printf("INFO: writing public key to %s.\n", argv[1]);
  } else {
    printf("ERROR: could not open %s for writing.\nAborting\n", argv[1]);
    return -6;
  }

  return 0;
}