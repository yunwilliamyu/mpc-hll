#include <stdio.h>
#include "elgamal.h"
#include <assert.h>

int main(void) {
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }



}
