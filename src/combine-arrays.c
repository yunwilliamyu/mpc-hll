#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "elgamal.h"

// Combines together a collection of ElGamal CipherTexts (by adding)

int main( int argc, char *argv[] ) {
  if (argc < 3) {
    printf(
      "Usage:\n"
      "  %s combined.bin [node1.bin node2.bin ... nodeN.bin]\n\n"
      "Generates a combined array of ciphertexts by adding together a\n"
      "list of individual arrays of ciphertexts.\n"
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
    } else {
      fns[j++] = argv[i];
    }
  }
  return combine_binary_CipherText_files(fns[0], &fns[1], j-1);
}
