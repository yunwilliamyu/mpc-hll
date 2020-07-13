// keygen-node.c
#include <stdio.h>
#include <stdbool.h>
#include "elgamal.h"

int main( int argc, char *argv[] ) {
  if (argc < 3) {
    printf(
      "Usage:\n"
      "  %s private.key public.key\n\n"
      "Generates/validates a partial public/private key\n\n"
      "The partial public key should be sent to the server,\n"
      "and the partial private key kept safe for later partial\n"
      "decryption.\n\n"
      "If files already exist, will attempt to use them.\n"
      "Note that although the public key can be generated from\n"
      "the public key, the opposite is not true.\n"
      "If both files exist, will validate that they are a proper\n"
      "key pair.\n"
      , argv[0]);
    return 1;
  }
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  unsigned char buffer[crypto_core_ristretto255_SCALARBYTES + 1];
  // Try to read privkey.
  // If it's the right size for a private key (32 bytes), use it.
  // If no such file exists, create a private key and write it
  // If it exists and is not the right size, fail loudly.
  FILE *privkey_file = fopen(argv[1], "rb");
  FILE *pubkey_file = fopen(argv[2], "rb");
  size_t bytes_read = 0;
  struct PrivateKey privkey;
  struct PublicKey pubkey;
  bool privkey_init = false;
  bool pubkey_init = false;
  // Test if privkey_file exists already and is a private key
  if (read_privkey(&privkey, argv[1])==0) {
    privkey_init = true;
  } else {
    privkey_init = false;
  }

  // Tests if pubkey_file exists already and is a public key
  if (read_pubkey(&pubkey, argv[2])==0) {
    pubkey_init = true;
  } else {
    pubkey_init = false;
  }

  if (pubkey_init) {
    if (!privkey_init) {
      printf("ERROR: cannot generate private key from public key.\nAborting\n");
      return -20;
    }
  }

  size_t bytes_written;
  // If private key file didn't exist, generate it now.
  if (privkey_init == false) {
    printf("INFO: %s does not exist. Generating...\n", argv[1]);
    generate_key(&privkey);
    privkey_file = fopen(argv[1], "wb");
    if (write_privkey(privkey, argv[1]) != 0) { return -12; }
    privkey_init == true;
  }

  // If public key file didn't exist generate it now.
  if (pubkey_init == false) {
    printf("INFO: %s does not exist. Generating...\n", argv[2]);
    if (priv2pub(&pubkey, privkey)!=0) {return -10;}
    if (write_pubkey(pubkey, argv[2]) != 0) {return -11;}
    pubkey_init == true;
  }

  // Validate that we have a valid public/private key pair
  struct PublicKey pubkey_tmp;
  if (priv2pub(&pubkey_tmp, privkey)!=0) {return -10;}
  if (memcmp(pubkey_tmp.val, pubkey.val, crypto_core_ristretto255_BYTES)==0) {
    printf("INFO: Public/private keys validated\n");
  } else {
    printf("ERROR: Public/private keys could not be validated.\nDo NOT use.\nAborting\n");
    return -30;
  }
return 0;
}
