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
  if (privkey_file) {
    bytes_read = fread(buffer, 1, crypto_core_ristretto255_SCALARBYTES + 1, privkey_file);
    if (bytes_read != crypto_core_ristretto255_SCALARBYTES) {
      printf("ERROR: %s exists and is not a private key file.\nAborting\n", argv[1]);
      return -2;
    } else {
      printf("INFO: Using %s as private key.\n", argv[1]);
      memcpy(privkey.val, buffer, crypto_core_ristretto255_SCALARBYTES);
      privkey_init = true;
    }
    fclose(privkey_file);
  }

  // Tests if pubkey_file exists already and is a public key
  if (pubkey_file) {
    bytes_read = fread(buffer, 1, crypto_core_ristretto255_BYTES + 1, pubkey_file);
    if (bytes_read != crypto_core_ristretto255_BYTES) {
      printf("ERROR: %s exists and is not a public key file.\nAborting\n", argv[2]);
      return -2;
    } else {
      printf("INFO: Using %s as public key.\n", argv[2]);
      memcpy(pubkey.val, buffer, crypto_core_ristretto255_SCALARBYTES);
      pubkey_init = true;
    }
    fclose(pubkey_file);
  }

  if (pubkey_init) {
    if (!privkey_init) {
      printf("ERROR: cannot generate private key from public key.\nAborting\n");
      return -20;
    }
  }

  // If private key file didn't exist, generate it now.
  size_t bytes_written = 0;
  if (privkey_init == false) {
    printf("INFO: %s does not exist. Generating...\n", argv[1]);
    generate_key(&privkey);
    privkey_file = fopen(argv[1], "wb");
    if (privkey_file) {
      printf("INFO: %s written to file\n", argv[1]);
      bytes_written = fwrite(privkey.val, 1, crypto_core_ristretto255_SCALARBYTES, privkey_file);
      if (bytes_written != crypto_core_ristretto255_SCALARBYTES) {
        printf("ERROR: incorrect number of bytes written to %s.\nAborting\n", argv[1]);
        return -3;
      }
    } else {
      printf("ERROR: could not open %s for writing.\nAborting\n", argv[1]);
      return -4;
    }
    privkey_init == true;
  }

  // If public key file didn't exist generate it now.
  if (pubkey_init == false) {
    printf("INFO: %s does not exist. Generating...\n", argv[2]);
    if (priv2pub(&pubkey, privkey)!=0) {return -10;}
    pubkey_file = fopen(argv[2], "wb");
    if (pubkey_file) {
      printf("INFO: %s written to file\n", argv[2]);
      bytes_written = fwrite(pubkey.val, 1, crypto_core_ristretto255_BYTES, pubkey_file);
      if (bytes_written != crypto_core_ristretto255_BYTES) {
        printf("ERROR: incorrect number of bytes written to %s.\nAborting\n", argv[2]);
        return -3;
      }
    } else {
      printf("ERROR: could not open %s for writing.\nAborting\n", argv[2]);
      return -4;
    }
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
