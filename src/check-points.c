#include <stdio.h>
#include "elgamal.h"

int main ( int argc, char *argv[]) {
  if (argc != 2) {
    printf(
        "Usage:\n"
        "  %s tobechecked.bin\n", argv[0]);
  }
  if (sodium_init() < 0 ) {
    exit(-1);
  }
  FILE *fp = fopen(argv[1], "rb");
  size_t bytes_read = 0;
  unsigned char *buffer;
  ssize_t size;
  if (fp) {
    fseek (fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);
    if (size < 0) { return -1; }
    info_print("Reading %li bytes\n", size);
    buffer = (unsigned char *)malloc((size_t)size);
    fread(buffer, 1, (size_t)size, fp);
    fclose(fp);
  }

  for (int i=0; i<(size / crypto_core_ristretto255_BYTES); i++) {
    if (crypto_core_ristretto255_is_valid_point(&(buffer[i*crypto_core_ristretto255_BYTES])) != 1) {
      error_print("ERROR: Item %i is not a valid code point\n", i);
    }
  }
  free(buffer);
  info_print("Nothing went wrong\n");
  return 0;

}
