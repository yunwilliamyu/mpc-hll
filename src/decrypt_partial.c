#include <stdio.h>
#include "elgamal.h"
#include <assert.h>

int main( int argc, char *argv[]) {
  if (argc != 4) {
    printf(
      "Usage:\n"
      "  %s shared_secrets.ss input.bin output.txt\n\n"
      "Outputs a partial decryption shared secret binary file\n"
      , argv[0]);
    return 1;
  }
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  return decrypt_bucket_file_with_sec(argv[1], argv[2], argv[3]);
}
