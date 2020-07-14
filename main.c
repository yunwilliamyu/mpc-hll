#include <stdio.h>
#include "elgamal.h"
#include <assert.h>

/* some convenience structs */

int main(void) {
  if (sodium_init() < 0) {
    /* Panic!  library couldn't be initialized */
    exit(-1);
  }
  char x[128];

  struct PrivateKey priv_key;
  generate_key(&priv_key);
  sodium_bin2hex(x, 128, priv_key.val, sizeof(priv_key.val));
  printf("Private Key: %s\n", x);
  struct PublicKey pub_key;
  if (priv2pub(&pub_key, priv_key) != 0) { return -1; }
  sodium_bin2hex(x, 128, pub_key.val, sizeof(pub_key.val));
  printf("Public Key: %s\n", x);

  struct PlainText msg;
  //crypto_core_ristretto255_random(msg.val);
  unsigned int message_int = 300;
  printf("Message: %i\n", message_int);
  encode(&msg, message_int);
  sodium_bin2hex(x, 128, msg.val, sizeof(msg.val));
  printf("Unencrypted: %s\n", x);
  struct CipherText emsg;
  if (encrypt(&emsg, msg, pub_key) != 0) {
    return -1;
  }
  struct CipherText emsg2;
  if (add_ciphertext(&emsg2, emsg, emsg) != 0) {return -1;}
  emsg = emsg2;

  sodium_bin2hex(x, 128, emsg.c1, sizeof(emsg.c1));
  printf("Encrypted: %s\t", x);
  sodium_bin2hex(x, 128, emsg.c2, sizeof(emsg.c2));
  printf("%s\n", x);
  struct PlainText dmsg;
  decrypt(&dmsg, emsg, priv_key);
  sodium_bin2hex(x, 128, dmsg.val, sizeof(dmsg.val));
  printf("Decrypted: %s\n", x);
  int message_decoded = -1;
  message_decoded = decode(dmsg);
  printf("Decoded: %i\n", message_decoded);
  assert(decode_equal(dmsg, 600)==0);





}
