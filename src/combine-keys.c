// keygen-node.c
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "elgamal.h"

// Combines together a collection of ElGamal keys

int main( int argc, char *argv[] ) {
  if (argc < 3) {
    printf(
      "Usage:\n"
      "  %s [-public/-private] combined.key [node1.key node2.key ... nodeN.key]\n\n"
      "Generates a combined key by adding together a\n"
      "list of individual keys.\n\n"
      "Will default to assuming that the keys are public keys unless -private\n"
      "is specified.\n"
      , argv[0]);
    return 1;
  }
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  bool private = false;
  int num_opts_given = 0;
  char *fns[argc];
  int j = 0;
  for (int i=1; i<argc; i++) {
    if (argv[i][0]=='-') { 
      num_opts_given++;
      if (strcmp(argv[i], "-private")==0) {
        info_print("INFO: Reading keys as private keys\n");
        private = true;
      } else if (strcmp(argv[i], "-public")==0) {
        info_print("INFO: Reading keys as public keys\n");
      } else {
        error_print("ERROR: unknown option: %s\n", argv[i]);
        return -100;
      }
    } else {
      fns[j++] = argv[i];
    }
  }
  if (private) {
    return combine_private_keys(fns[0], &fns[1], j-1);
  } else {
    return combine_public_keys(fns[0], &fns[1], j-1);
  }
}
