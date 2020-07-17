// elgamal_test.cpp
#include <stdio.h>
#include <string.h>
//#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "elgamal.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

/* ******************************
*  Suite 1 - ElGamal tests
* ***************************** */
int init_suite(void);
int clean_suite(void);
void test_roundtrip(void);
void test_zero(void);
void test_add(void);
void test_private_equality(void);
void test_private_not_equality(void);
void test_roundtrip_rolling(void);
void test_roundtrip_array(void);
void test_array_max(void);

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

  struct UnrolledCipherText uct;
  unsigned char x = 0;
  for (int i = 0; i<=BUCKET_MAX; i++ ) {
    CU_ASSERT(unroll(&uct, i, pub_key) == 0);
    CU_ASSERT(reroll(&x, uct, priv_key) == 0);
    CU_ASSERT(x == i);
    //printf("\n%i:%i\n", i, x);
  }
  // Test out of bounds
  //CU_ASSERT(unroll(&uct, 0, pub_key) == -1);
  CU_ASSERT(unroll(&uct, 65, pub_key) == -1);
}

void test_roundtrip_array(void) {
  unsigned int num = BUCKET_MAX * 2;
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  unsigned char arr[num+1];
  for (unsigned int i=0; i<num; i++) {arr[i] = i % BUCKET_MAX; }
  arr[num-1]=BUCKET_MAX;
  arr[num]=255;
  unsigned char earr[(num)*(sizeof (((struct UnrolledCipherText*)0)->arr))];
  //printf("\n%lu\n", sizeof earr);
  int size = encrypt_array(earr, arr, pub_key, num);
  CU_ASSERT(size == (int)num);
  //printf("\n%i:%i\n", size, (int)num);
  unsigned char uarr[num+1];
  CU_ASSERT(decrypt_array(uarr, earr, priv_key, (unsigned int)size)==size);
  CU_ASSERT(memcmp(uarr, arr, num) == 0);
  CU_ASSERT(uarr[num]==0);
}

void test_array_max(void) {
  struct PrivateKey priv_key;
  generate_key(&priv_key);
  struct PublicKey pub_key;
  CU_ASSERT(priv2pub(&pub_key, priv_key) == 0);

  unsigned int num = BUCKET_MAX * 2;
  unsigned char arr[num+1];
  for (unsigned int i=0; i<num; i++) {arr[i] = i % (BUCKET_MAX+1); }
  arr[num]=255;
  unsigned char earr[(num)*(sizeof (((struct UnrolledCipherText*)0)->arr))];
  int size = encrypt_array(earr, arr, pub_key, num);
  CU_ASSERT(size == (int)num);

  unsigned char arr2[num+1];
  for (unsigned int i=0; i<num; i++) {arr2[i] = (i+5) % (BUCKET_MAX+1); }
  arr2[num]=255;
  unsigned char earr2[(num)*(sizeof (((struct UnrolledCipherText*)0)->arr))];
  int size2 = encrypt_array(earr2, arr2, pub_key, num);
  CU_ASSERT(size2 == (int)num);

  unsigned char arr3[num+1];
  for (unsigned int i=0; i<num; i++) {arr3[i] = arr[i] > arr2[i] ? arr[i] : arr2[i];}
  unsigned char earr3[(num)*(sizeof (((struct UnrolledCipherText*)0)->arr))];
  //int size3 = encrypt_array(earr3, arr3, pub_key, num);
  //CU_ASSERT(size3 == (int)num);
  CU_ASSERT(array_max_in_place(earr, earr2, (int)num) == 0);
  memcpy(earr3, earr, sizeof earr3);

  unsigned char uarr[num+1];
  CU_ASSERT(decrypt_array(uarr, earr3, priv_key, (unsigned int)size)==size);
  CU_ASSERT(memcmp(uarr, arr3, num) == 0);
  CU_ASSERT(uarr[num]==0);

  
}

/* ******************************
*  Suite 2 - IO tests
* ***************************** */
int init_suite2(void);
int clean_suite2(void);
void test_distributed_keygen(void);

int init_suite2(void) {
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    return -1;
  }
  return 0;
}
int clean_suite2(void) {return 0; }

void test_distributed_keygen(void) {
  char tmpdir[64];
  snprintf(tmpdir, 64, "tmp%lu-%d", (unsigned long)time(NULL), rand());
  int ncount = 5;
  char node_privkey_fns[ncount][128];
  char node_pubkey_fns[ncount][128];

  char *node_privkey_fns_ptrs[ncount];
  char *node_pubkey_fns_ptrs[ncount];
  for (int i=0; i<ncount; i++) {
    node_privkey_fns_ptrs[i] = (node_privkey_fns[i]);
    node_pubkey_fns_ptrs[i] = (node_pubkey_fns[i]);
  }

  //printf("%s",str);
  CU_ASSERT(mkdir(tmpdir, 0777)==0);
  for (int i=0; i<ncount; i++) {
    char tmpfn[16];
    snprintf(node_privkey_fns[i], 128, "%s/node%d.priv", tmpdir, i);
    snprintf(node_pubkey_fns[i], 128, "%s/node%d.pub", tmpdir, i);
    CU_ASSERT(keygen_node(node_privkey_fns[i], node_pubkey_fns[i])==0);
  }
  char comb_priv_fn[128];
  snprintf(comb_priv_fn, 128, "%s/combined.priv", tmpdir);
  char comb_pub_fn[128];
  snprintf(comb_pub_fn, 128, "%s/combined.pub", tmpdir);
  CU_ASSERT(combine_private_keys(comb_priv_fn, node_privkey_fns_ptrs, ncount)==0);
  CU_ASSERT(combine_public_keys(comb_pub_fn, node_pubkey_fns_ptrs, ncount)==0);
  struct PrivateKey comb_privkey;
  struct PublicKey comb_pubkey;
  CU_ASSERT(read_privkey(&comb_privkey, comb_priv_fn)==0);
  CU_ASSERT(read_pubkey(&comb_pubkey, comb_pub_fn)==0);
  struct PublicKey comb_pubkey2;
  CU_ASSERT(priv2pub(&comb_pubkey2, comb_privkey) == 0);
  CU_ASSERT(sodium_memcmp(comb_pubkey.val, comb_pubkey2.val, sizeof comb_pubkey2.val) == 0);
  
}


/* ******************************
* Actually run all the tests
* ***************************** */
int main() {
  CU_pSuite pSuite1 = NULL;
  CU_pSuite pSuite2 = NULL;

  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  pSuite1 = CU_add_suite("Elgamal_Tests", init_suite, clean_suite);
  if (NULL == pSuite1) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  pSuite2 = CU_add_suite("IO_tests", init_suite2, clean_suite2);
  if (NULL == pSuite2) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if ( // Test Suite 1
      (NULL == CU_add_test(pSuite1, "Testing round trip.....", test_roundtrip)),
      (NULL == CU_add_test(pSuite1, "Testing encoding 0s.....", test_zero)),
      (NULL == CU_add_test(pSuite1, "Testing addition.....", test_add)),
      (NULL == CU_add_test(pSuite1, "Testing private equality.....", test_private_equality)),
      (NULL == CU_add_test(pSuite1, "Testing private not equality.....", test_private_not_equality)),
      (NULL == CU_add_test(pSuite1, "Testing roundtrip rolling.....", test_roundtrip_rolling)),
      (NULL == CU_add_test(pSuite1, "Testing roundtrip array.....", test_roundtrip_array)),
      (NULL == CU_add_test(pSuite1, "Testing array max.....", test_array_max)),
      // Test Suite 2
      (NULL == CU_add_test(pSuite2, "Testing distributed keygen.....", test_distributed_keygen))
      ) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();

}

