// keygen-node.c
#include <stdio.h>
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
  return keygen_node(argv[1], argv[2]);
}
