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

void test_zero(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  struct PlainText msg1;
  CU_ASSERT(encode(&msg1, 0) == -1); // Because we are deliberately encoding 0, so return value will be -1
  struct CipherText emsg1;
  CU_ASSERT(encrypt(&emsg1, msg1, pub_key) == 0);
//  char x[128];
//  sodium_bin2hex(x, 128, msg1.val, sizeof(msg1.val));
//  printf("\nx: %s\n", x);
//  sodium_bin2hex(x, 128, emsg1.c1, sizeof(emsg1.c1));
//  printf("\nc1: %s\n", x);
//  sodium_bin2hex(x, 128, emsg1.c2, sizeof(emsg1.c2));
//  printf("\nc1: %s\n", x);
}

void test_add(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  struct PlainText msg1;
  CU_ASSERT(encode(&msg1, 111) == 0);
  struct CipherText emsg1;
  CU_ASSERT(encrypt(&emsg1, msg1, pub_key) == 0);
  struct PlainText msg2;
  encode(&msg2, 222);
  struct CipherText emsg2;
  CU_ASSERT(encrypt(&emsg2, msg2, pub_key) == 0);
  struct CipherText emsg_sum;
  CU_ASSERT(add_ciphertext(&emsg_sum, emsg1, emsg2) == 0);
  struct PlainText dmsg;
  CU_ASSERT(decrypt(&dmsg, emsg_sum, priv_key) == 0);
  CU_ASSERT(decode_equal(dmsg, 333)==0);
}

void test_private_equality(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  struct PlainText msg1;
  CU_ASSERT(encode(&msg1, 31) == 0);
  struct CipherText emsg1;
  CU_ASSERT(encrypt(&emsg1, msg1, pub_key) == 0);
  struct PlainText msg2;
  CU_ASSERT(encode(&msg2, 31) == 0);
  struct CipherText emsg2;
  CU_ASSERT(encrypt(&emsg2, msg2, pub_key) == 0);
  struct CipherText emsg_equal;
  CU_ASSERT(private_equality_test(&emsg_equal, emsg1, emsg2) == 0);
  struct PlainText dmsg;
  CU_ASSERT(decrypt(&dmsg, emsg_equal, priv_key) == 0);
  CU_ASSERT(decode_equal(dmsg, 0)==0);

 // char x[128];
 // sodium_bin2hex(x, 128, emsg_equal.c1, sizeof(emsg_equal.c1));
 // printf("\nc1: %s\n", x);
 // sodium_bin2hex(x, 128, emsg_equal.c2, sizeof(emsg_equal.c2));
 // printf("c2: %s\n", x);
}

void test_private_not_equality(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  struct PlainText msg1;
  CU_ASSERT(encode(&msg1, 314) == 0);
  struct CipherText emsg1;
  CU_ASSERT(encrypt(&emsg1, msg1, pub_key) == 0);
  struct PlainText msg2;
  CU_ASSERT(encode(&msg2, 315) == 0);
  struct CipherText emsg2;
  CU_ASSERT(encrypt(&emsg2, msg2, pub_key) == 0);
  struct CipherText emsg_equal;
  CU_ASSERT(private_equality_test(&emsg_equal, emsg1, emsg2) == 0);
  struct PlainText dmsg;
  CU_ASSERT(decrypt(&dmsg, emsg_equal, priv_key) == 0);
  CU_ASSERT(decode_equal(dmsg, 0)!=0);

//  char x[128];
//  sodium_bin2hex(x, 128, emsg_equal.c1, sizeof(emsg_equal.c1));
//  printf("\nc1: %s\n", x);
//  sodium_bin2hex(x, 128, emsg_equal.c2, sizeof(emsg_equal.c2));
//  printf("c2: %s\n", x);
}

void test_roundtrip_rolling(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  struct UnrolledCipherText64 uct;
  unsigned char x = 0;
  for (int i = 1; i<=64; i++ ) {
    CU_ASSERT(unroll(&uct, i, pub_key) == 0);
    CU_ASSERT(reroll(&x, uct, priv_key) == 0);
    CU_ASSERT(x == i);
    //printf("\n%i\n", x);
  }
  // Test out of bounds
  CU_ASSERT(unroll(&uct, 0, pub_key) == -1);
  CU_ASSERT(unroll(&uct, 65, pub_key) == -1);
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
      (NULL == CU_add_test(pSuite1, "Testing round trip.....", test_roundtrip)),
      (NULL == CU_add_test(pSuite1, "Testing encoding 0s.....", test_zero)),
      (NULL == CU_add_test(pSuite1, "Testing addition.....", test_add)),
      (NULL == CU_add_test(pSuite1, "Testing private equality.....", test_private_equality)),
      (NULL == CU_add_test(pSuite1, "Testing private not equality.....", test_private_not_equality)),
      (NULL == CU_add_test(pSuite1, "Testing roundtrip rolling.....", test_roundtrip_rolling))
      ) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();

}

