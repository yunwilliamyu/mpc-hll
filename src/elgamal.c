// ELGAMAL.C
#include "elgamal.h"

/* generates a random scalar as a private elgamal key */
int generate_key(struct PrivateKey *a) {
  crypto_core_ristretto255_scalar_random(a->val);
  return 0;
}

/* generates a public elgamal key from a private key by taking g^priv.val */
int priv2pub(struct PublicKey *a, const struct PrivateKey priv) {
  if (crypto_scalarmult_ristretto255_base(a->val, priv.val) != 0) {
    return -1;
  }
  return 0;
}

/* performs elgamal encryption */
int encrypt(struct CipherText *a, const struct PlainText plain, const struct PublicKey pub) {
  unsigned char y[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(y);
  unsigned char s[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(s, y, pub.val) != 0) {
    return -1;
  }
  crypto_scalarmult_ristretto255_base(a->c1, y);
  if (crypto_core_ristretto255_add(a->c2, plain.val, s) != 0) {
    return -1;
  }
  return 0;
}

/* decrypts elgamal encryption */
int decrypt(struct PlainText *a, const struct CipherText x, const struct PrivateKey key) {
  unsigned char s[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(s, key.val, x.c1) != 0) {
    return -1;
  }
  if (crypto_core_ristretto255_sub(a->val, x.c2, s) != 0) {
    return -1;
  }
  return 0;
}

/* encodes an unsigned int as a PlainText Ristretto point message
 *
 * Will return -1 if message=0, or 0 otherwise.
 * */
int encode(struct PlainText *a, unsigned int message) {
  unsigned char s[crypto_core_ristretto255_SCALARBYTES];
  memset(s, 0, sizeof s);
  //s[0] = message;
  memcpy(s,(char*)&message, sizeof(unsigned int));
  return crypto_scalarmult_ristretto255_base(a->val, s);
}

/* add ciphertexts */
int add_ciphertext(struct CipherText *a, const struct CipherText x, const struct CipherText y) {
  if (crypto_core_ristretto255_add(a->c1, x.c1, y.c1) != 0) {
    return -1;
  }
  if (crypto_core_ristretto255_add(a->c2, x.c2, y.c2) != 0) {
    return -1;
  }
  return 0;
}


// decodes a Ristretto point message to a byte with value 1 to 255 inclusive.
// returns 0 on failure (i.e. not in range [1,255])
// returns value if within that range
unsigned char decode(const struct PlainText x) {
  unsigned char a = 0;
  unsigned char s[crypto_core_ristretto255_SCALARBYTES];
  struct PlainText guess;
  memset(s, 0, sizeof s);
  for (int i=1; i<256; i++) {
    s[0]=i;
    crypto_scalarmult_ristretto255_base(guess.val, s);
    if (memcmp(guess.val, x.val, crypto_core_ristretto255_BYTES)==0) {
      a = i % 256;
      return a;
    }
  }
  return a;
}

/* tests if a Ristretto point message decrypts to a particular integer
 * returns -1 on failure (i.e. not equal)
 * returns 0 on success (i.e. equal)
 * */
int decode_equal(const struct PlainText x, unsigned int y) {
  unsigned char s[crypto_core_ristretto255_SCALARBYTES];
  struct PlainText guess;
  memset(s, 0, sizeof s);
  memcpy(s,(char*)&y, sizeof(unsigned int));
  crypto_scalarmult_ristretto255_base(guess.val, s);
  if (memcmp(guess.val, x.val, crypto_core_ristretto255_BYTES)==0) {
    return 0;
  }
  return -1;
}

/* Puts an enciphered 0 into "a" if the two are equal. Otherwise "a" is an enciphered random number
 *
 * returns 0 on success, and -1 on failure
 *
 * https://crypto.stackexchange.com/questions/9527/how-does-an-oblivious-test-of-plaintext-equality-work
*/
int private_equality_test(struct CipherText *a, const struct CipherText x, const struct CipherText y) {
  // t.c1 = x.c1 - y.c1
  // t.c2 = x.c2 - y.c2
  // z = randint(0, L)
  // a->c1 = t.c1 * z
  // a->c2 = t.c2 * z
  struct CipherText t;
  if (crypto_core_ristretto255_sub(t.c1, x.c1, y.c1) != 0) {return -1; }
  if (crypto_core_ristretto255_sub(t.c2, x.c2, y.c2) != 0) {return -1; }
  unsigned char z[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(z);
  if (crypto_scalarmult_ristretto255(a->c1, z, t.c1) != 0) {return -1; }
  if (crypto_scalarmult_ristretto255(a->c2, z, t.c2) != 0) {return -1; }
  return 0;
}

/* Unrolls an int x=4 into an encrypted array [r, r, r, r, 0, 0, ..., 0], where
 *   each r is a random value
 *   x is the number of r's
 *   the length of the array = 64
 *
 * Puts the result into "a", and returns 0 on success, -1 on failure
 * */
int unroll(struct UnrolledCipherText64 *a, const unsigned char x, const struct PublicKey pub_key) {
  struct PlainText tmp_plain;
  // Can only encode values from 1 to 64
  if (x > 64) {return -1; }
  if (x == 0 ) { return -1; }
  for (int i=0; i<x; i++) {
    crypto_core_ristretto255_random(tmp_plain.val);
    if (encrypt( &(a->arr[i]), tmp_plain, pub_key) != 0) {return -1; }
  }
  for (int i=x; i<64; i++) {
    if (encode(&tmp_plain, 0) != -1) {return -1; }
    if (encrypt( &(a->arr[i]), tmp_plain, pub_key) != 0) {return -1; }
  }
  return 0;
}

/* Rerolls and decrypts an UnrolledCipherText64 back into an integer from 1 to 64 */
int reroll(unsigned char *a, const struct UnrolledCipherText64 uct, const struct PrivateKey priv_key) {
  struct PlainText tmp_plain;
  for (int i=0; i<64; i++) {
    if (decrypt(&tmp_plain, uct.arr[i], priv_key)!=0) {return -1;}
    if (decode_equal(tmp_plain, 0)==0) {
      *a = i;
      return 0;
    }
  }
  *a = 64;
  return 0;
}

/* Tests if Public Key file exists already, is a public key, and if so,
 * reads the file into struct
 *
 * We are deliberately very strict and will return an error if anything
 * seems wrong.
 *
 * We will return 0 on success and a nonzero value on failure
 * */
int read_pubkey(struct PublicKey *a, const char *fn) {
  unsigned char buffer[crypto_core_ristretto255_SCALARBYTES + 1];
  FILE *pubkey_file = fopen(fn, "rb");
  size_t bytes_read = 0;
  if (pubkey_file) {
    bytes_read = fread(buffer, 1, crypto_core_ristretto255_BYTES + 1, pubkey_file);
    if ((bytes_read != crypto_core_ristretto255_BYTES) ||
        (crypto_core_ristretto255_is_valid_point(buffer)==0)){
      error_print("ERROR: %s exists and is not a public key file.\n", fn);
      return -2;
    } else {
      info_print("INFO: Using %s as public key.\n", fn);
      memcpy(a->val, buffer, crypto_core_ristretto255_BYTES);
      return 0;
    }
    fclose(pubkey_file);
  }
  return -1;
}

/* Writes Public Key out to a file from a struct.
 */
int write_pubkey(const struct PublicKey pubkey, const char *fn) {
  size_t bytes_written = 0;
  FILE *key_file = fopen(fn, "wb");
  if (key_file) {
    bytes_written = fwrite(pubkey.val, 1, crypto_core_ristretto255_BYTES, key_file);
    if (bytes_written != crypto_core_ristretto255_BYTES) {
        error_print("ERROR: incorrect number of bytes written to %s.\n", fn);
        return -5;
    }
    info_print("INFO: writing public key to %s.\n", fn);
    fclose(key_file);
    return 0;
  } else {
    error_print("ERROR: could not open %s for writing.\n", fn);
    return -6;
  }
}

/* Tests if Private Key file exists already, is a private key, and if so,
 * reads the file into struct
 *
 * We are deliberately very strict and will return an error if anything
 * seems wrong.
 *
 * We will return 0 on success and a nonzero value on failure
 * */
int read_privkey(struct PrivateKey *a, const char *fn) {
  unsigned char buffer[crypto_core_ristretto255_SCALARBYTES + 1];
  FILE *privkey_file = fopen(fn, "rb");
  size_t bytes_read = 0;
  if (privkey_file) {
    bytes_read = fread(buffer, 1, crypto_core_ristretto255_SCALARBYTES + 1, privkey_file);
    if (bytes_read != crypto_core_ristretto255_SCALARBYTES){
      error_print("ERROR: %s exists and is not a private key file.\n", fn);
      return -2;
    } else {
      info_print("INFO: Using %s as private key.\n", fn);
      memcpy(a->val, buffer, crypto_core_ristretto255_SCALARBYTES);
      return 0;
    }
    fclose(privkey_file);
  }
  return -1;
}

/* Writes Private Key out to a file from a struct.
 */
int write_privkey(const struct PrivateKey privkey, const char *fn) {
  size_t bytes_written = 0;
  FILE *key_file = fopen(fn, "wb");
  if (key_file) {
    bytes_written = fwrite(privkey.val, 1, crypto_core_ristretto255_SCALARBYTES, key_file);
    if (bytes_written != crypto_core_ristretto255_SCALARBYTES) {
        error_print("ERROR: incorrect number of bytes written to %s.\n", fn);
        return -5;
    }
    info_print("INFO: writing private key to %s.\n", fn);
    fclose(key_file);
    return 0;
  } else {
    error_print("ERROR: could not open %s for writing.\n", fn);
    return -6;
  }
}


int keygen_node(char *private_fn, char *public_fn) {
  FILE *privkey_file = fopen(private_fn, "rb");
  FILE *pubkey_file = fopen(public_fn, "rb");

  unsigned char buffer[crypto_core_ristretto255_SCALARBYTES + 1];
  // Try to read privkey.
  // If it's the right size for a private key (32 bytes), use it.
  // If no such file exists, create a private key and write it
  // If it exists and is not the right size, fail loudly.
  size_t bytes_read = 0;
  struct PrivateKey privkey;
  struct PublicKey pubkey;
  bool privkey_init = false;
  bool pubkey_init = false;
  // Test if privkey_file exists already and is a private key
  if (read_privkey(&privkey, private_fn)==0) {
    privkey_init = true;
  } else {
    privkey_init = false;
  }

  // Tests if pubkey_file exists already and is a public key
  if (read_pubkey(&pubkey, public_fn)==0) {
    pubkey_init = true;
  } else {
    pubkey_init = false;
  }

  if (pubkey_init) {
    if (!privkey_init) {
      error_print("ERROR: cannot generate private key from public key.\nAborting\n");
      return -20;
    }
  }

  size_t bytes_written;
  // If private key file didn't exist, generate it now.
  if (privkey_init == false) {
    info_print("INFO: %s does not exist. Generating...\n", private_fn);
    generate_key(&privkey);
    privkey_file = fopen(private_fn, "wb");
    if (write_privkey(privkey, private_fn) != 0) { return -12; }
    privkey_init == true;
  }

  // If public key file didn't exist generate it now.
  if (pubkey_init == false) {
    info_print("INFO: %s does not exist. Generating...\n", public_fn);
    if (priv2pub(&pubkey, privkey)!=0) {return -10;}
    if (write_pubkey(pubkey, public_fn) != 0) {return -11;}
    pubkey_init == true;
  }

  // Validate that we have a valid public/private key pair
  struct PublicKey pubkey_tmp;
  if (priv2pub(&pubkey_tmp, privkey)!=0) {return -10;}
  if (memcmp(pubkey_tmp.val, pubkey.val, crypto_core_ristretto255_BYTES)==0) {
    info_print("INFO: Public/private keys validated\n");
  } else {
    error_print("ERROR: Public/private keys could not be validated.\nDo NOT use.\nAborting\n");
    return -30;
  }
  return 0;
  
}

// Generates a combined public key by adding together
// the list of node public keys
int combine_public_keys(char *combined_fn, char **node_fns, const int ncount) {
  FILE *combined_key_file = fopen(combined_fn, "rb");
  if (combined_key_file) {
    error_print("ERROR: %s exists.\nAborting so we don't clobber it.\n", combined_fn);
    fclose(combined_key_file);
    return -2;
  }
  FILE *node_key_file;
  unsigned char buffer[crypto_core_ristretto255_BYTES + 1];
  size_t bytes_read = 0;
  struct PublicKey combkey;
  memset(combkey.val, 0, sizeof combkey.val);
  struct PublicKey tempkey;
  memset(tempkey.val, 0, sizeof tempkey.val);
  struct PublicKey nodekey;
  // Add together all of the node keys as points on Ristretto255
  for (int file_it=0; file_it<ncount; file_it++) {
    if (read_pubkey(&nodekey, node_fns[file_it])==0) {
      if (crypto_core_ristretto255_add(combkey.val, tempkey.val, nodekey.val)!=0) {
        error_print("ERROR: problem adding %s to combined key.\nAborting\n", node_fns[file_it]);
        return -4;
      }
      memcpy(tempkey.val, combkey.val, crypto_core_ristretto255_BYTES);
    } else {
      error_print("ERROR: could not open %s for reading.\n", node_fns[file_it]);
      return -10;
    }
  }

  // writing combined public key now
  size_t bytes_written = 0;
  if (write_pubkey(combkey, combined_fn) == 0) {
    // Do nothing
  } else {
    return -1;
  }
  return 0;
}

// Generates a combined private key by adding together
// the list of node private keys
int combine_private_keys(char *combined_fn, char **node_fns, const int ncount) {
  FILE *combined_key_file = fopen(combined_fn, "rb");
  if (combined_key_file) {
    error_print("ERROR: %s exists.\nAborting so we don't clobber it.\n", combined_fn);
    fclose(combined_key_file);
    return -2;
  }
  FILE *node_key_file;
  unsigned char buffer[crypto_core_ristretto255_SCALARBYTES + 1];
  size_t bytes_read = 0;
  struct PrivateKey combkey;
  memset(combkey.val, 0, sizeof combkey.val);
  struct PrivateKey tempkey;
  memset(tempkey.val, 0, sizeof tempkey.val);
  struct PrivateKey nodekey;
  // Add together all of the node keys as points on Ristretto255
  for (int file_it=0; file_it<ncount; file_it++) {
    if (read_privkey(&nodekey, node_fns[file_it])==0) {
      crypto_core_ristretto255_scalar_add(combkey.val, tempkey.val, nodekey.val) ;
      memcpy(tempkey.val, combkey.val, crypto_core_ristretto255_SCALARBYTES);
    } else {
      error_print("ERROR: could not open %s for reading.\n", node_fns[file_it]);
      return -10;
    }
  }

  // writing combined public key now
  size_t bytes_written = 0;
  if (write_privkey(combkey, combined_fn) == 0) {
    // Do nothing
  } else {
    return -1;
  }
  return 0;
}

// Returns the size of the array
// Returns negative value on error
int encrypt_array(unsigned char *out, const unsigned char *in, const struct PublicKey pubkey, const int max_elem) {
  int i = 0;
  struct PlainText uval;
  struct CipherText cval;
  while (in[i] != 0) {
    if (encode(&uval, in[i])!=0) {return -1;}
    if (encrypt(&cval, uval, pubkey)!=0) { return -1;}
    memcpy(&out[2*i*crypto_core_ristretto255_BYTES], cval.c1, crypto_core_ristretto255_BYTES );
    memcpy(&out[(2*i+1)*crypto_core_ristretto255_BYTES], cval.c2, crypto_core_ristretto255_BYTES );
    if (i++>max_elem) {
      error_print("ERROR: too many elements for size of array: %i\n", i);
      return -2;
    }
  }
  return i;
}

// Reads file into array. If items were read, return the number. Return a negative number upon error.
int read_file_to_array(unsigned char *ans, char *fn, size_t max) {
  FILE * fp = fopen(fn, "r");
  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  intmax_t val = 0;
  if (fp) {
    int i = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
      val = strtoimax(line, NULL, 10);
      if ((val >= 1) && (val <= 64)) {
        ans[i++] = val;
      } else {
        error_print("ERROR: value on line %i not a number in [1, 64].\n", i);
        return -1;
      }
      if (i > (int)max) {
        error_print("ERROR: exceeded maximum number of lines: %lu.\n", max);
        return -1;
      }
    }
    info_print("INFO: Read %i lines.\n", i);
    fclose(fp);
    return i;
  } else {
    error_print("ERROR: could not open %s for reading.\n", fn);
    return -1;
  }
}

int encrypt_file(char *key_fn, char *input_fn, char *output_fn) {
  struct PublicKey pub_key;
  int tmp;
  unsigned int size_of_array = 0;
  if ((tmp = read_pubkey(&pub_key, key_fn)!=0)) {return tmp; }
  unsigned char byte_array[10000];
  memset(byte_array, 0, sizeof byte_array);
  tmp = read_file_to_array(byte_array, input_fn, sizeof byte_array);
  if (tmp < 0) {
    error_print("ERROR: could not read file into array.\n");
    return tmp;
  } else {
    size_of_array = (unsigned int)tmp;
    error_print("%i\n", tmp);
  }
  /*
  for (unsigned int i=0; i<sizeof byte_array; i++) {
    if (byte_array[i] > 0) {
      printf("%i\n", byte_array[i]);
    } else {
      break;
    }
  }
  */
  unsigned char out_array[10000*crypto_core_ristretto255_SCALARBYTES];
  if ((tmp = encrypt_array(out_array, byte_array, pub_key, sizeof byte_array) < 0)){
    return tmp; // return error if less than 0
  }
  FILE *out_file = fopen(output_fn, "wb");
  size_t bytes_written = 0;
  if (out_file) {
    bytes_written = fwrite(out_array, 1, crypto_core_ristretto255_BYTES*size_of_array, out_file);
    if (bytes_written != crypto_core_ristretto255_BYTES*size_of_array) {
      error_print("ERROR: incorrect number of bytes written to %s.\n", output_fn);
      return -5;
    }
    info_print("INFO: Written %lu bytes to %s.\n", bytes_written, output_fn);
    fclose(out_file);
    return 0;
  } else {
    error_print("ERROR: could not open %s for writing.\n", output_fn);
    return -6;
  }
  return 0;
}





