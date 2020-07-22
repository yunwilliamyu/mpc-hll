#include <stdio.h>
#include "elgamal.h"
#include <assert.h>

int main( int argc, char *argv[]) {
  if (argc != 4) {
    printf(
      "Usage:\n"
      "  %s public.key input.txt output.bin\n\n"
      "Encrypts a newline delimited list of integers in [0,%i]\n"
      , argv[0], BUCKET_MAX);
    return 1;
  }
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  int result;
  result = encrypt_bucket_file(argv[1], argv[2], argv[3]);
  //result = encrypt_file("c", "b", "a");
  return result;
}
