// elgamal_test.cpp
#include <stdio.h>
#include <string.h>
//#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "elgamal.h"

int init_suite(void) {
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    return -1;
  }
  return 0;
}
int clean_suite(void) {return 0; }

void test_roundtrip(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  struct PlainText msg;
  crypto_core_ristretto255_random(msg.val);
  struct CipherText emsg;
  CU_ASSERT(encrypt(&emsg, msg, pub_key) == 0);
  struct PlainText dmsg;
  decrypt(&dmsg, emsg, priv_key);
  CU_ASSERT(sodium_memcmp(msg.val, dmsg.val, sizeof msg) == 0);
}

void test_add(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);
  struct PlainText msg;
  crypto_core_ristretto255_random(msg.val);
  struct CipherText emsg;
  CU_ASSERT(encrypt(&emsg, msg, pub_key) == 0);
  struct PlainText dmsg;
  decrypt(&dmsg, emsg, priv_key);
  CU_ASSERT(sodium_memcmp(msg.val, dmsg.val, sizeof msg) == 0);
}


int main() {
  CU_pSuite pSuite1 = NULL;

  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  pSuite1 = CU_add_suite("Elgamal_Tests", init_suite, clean_suite);
  if (NULL == pSuite1) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (
      (NULL == CU_add_test(pSuite1, "Testing round trip.....", test_roundtrip))
      ) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();

}

