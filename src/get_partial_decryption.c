#include <stdio.h>
#include "elgamal.h"
#include <assert.h>

int main( int argc, char *argv[]) {
  if (argc != 4) {
    printf(
      "Usage:\n"
      "  %s private.key input.bin output.ss\n\n"
      "Outputs a partial decryption shared secret binary file\n"
      , argv[0]);
    return 1;
  }
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  return get_partial_decryptions(argv[1], argv[2], argv[3]);
}
