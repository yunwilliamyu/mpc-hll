#include <stdio.h>
#include "elgamal.h"
#include <assert.h>

int main( int argc, char *argv[]) {
  if (argc != 4) {
    printf(
      "Usage:\n"
      "  %s private.key input.bin output.txt\n\n"
      "Decrypts to a newline delimited list of integers in [1,64]\n"
      , argv[0]);
    return 1;
  }
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  return decrypt_file(argv[1], argv[2], argv[3]);
}
