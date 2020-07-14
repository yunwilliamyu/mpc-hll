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
  return combine_public_keys(argv[1], &argv[2], argc - 2);
}
