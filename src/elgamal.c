// ELGAMAL.C
#include "elgamal.h"


int generate_key(struct PrivateKey *a) {
  crypto_core_ristretto255_scalar_random(a->val);
  return 0;
}

int priv2pub(struct PublicKey *a, const struct PrivateKey priv) {
  if (crypto_scalarmult_ristretto255_base(a->val, priv.val) != 0) {
    return -1;
  }
  return 0;
}

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

int decrypt(struct PlainText *a, const struct CipherText x, const struct PrivateKey key) {
  unsigned char s[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(s, key.val, x.c1) != 0) {
    char y[128];
    sodium_bin2hex(y, 128, x.c1, sizeof(x.c1));
    error_print("\nc1: %s\n", y);
    error_print("ERROR: Could not decrypt c1\n");
    return -1;
  }
  // a->val = x.c2 - s
  if (crypto_core_ristretto255_sub(a->val, x.c2, s) != 0) {
    error_print("ERROR: Could not decrypt c2\n");
    return -1;
  }
  return 0;
}

int decrypt_with_sec(struct PlainText *a, const struct CipherText x, const struct SharedSecret s) {
  if (crypto_core_ristretto255_sub(a->val, x.c2, s.val) != 0) {
    error_print("ERROR: Could not decrypt c2\n");
    return -1;
  }
  return 0;
}

int shared_secret(struct SharedSecret *s, const struct CipherText x, const struct PrivateKey key) {
  if (crypto_scalarmult_ristretto255(s->val, key.val, x.c1) != 0) {
    error_print("ERROR: Could not generate shared secret\n");
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

/* Unrolls an int x=4 into an plaintext array [r, r, r, r, 0, 0, ..., 0], where
 *   each r is a random value
 *   x is the number of r's
 *   the length of the array = BUCKET_MAX
 *
 * Puts the result into "a", and returns 0 on success, -1 on failure
 * */
int unroll(struct UnrolledPlainText *a, const unsigned char x) {
  // Can only encode values from 1 to BUCKET_MAX
  if (x > BUCKET_MAX) {return -1; }
  for (int i=0; i<x; i++) {
    crypto_core_ristretto255_random(a->arr[i].val);
  }
  for (int i=x; i<BUCKET_MAX; i++) {
    if (encode(&(a->arr[i]), 0) != -1) {return -1; }
  }
  return 0;
}

/* Unrolls an int x=4 into an ciphertext array [r, r, r, r, 0, 0, ..., 0], where
 *   each r is a random value
 *   x is the number of r's
 *   the length of the array = BUCKET_MAX
 *
 * Puts the result into "a", and returns 0 on success, -1 on failure
 * */
int unroll_and_encrypt(struct UnrolledCipherText *a, const unsigned char x, const struct PublicKey pub_key) {
  struct UnrolledPlainText upt;
  if (unroll(&upt, x) != 0) {return -1;};
  for (int i=0; i<BUCKET_MAX; i++) {
    if (encrypt( &(a->arr[i]), upt.arr[i], pub_key) != 0) {return -1; }
  }
  return 0;
}

/* rerolls and UnrolledPlainText back into an intger from 0 to BUCKET_MAX */
int reroll(unsigned char *a, const struct UnrolledPlainText upt) {
  for (int i=0; i<BUCKET_MAX; i++) {
    if (decode_equal(upt.arr[i], 0) == 0) {
      *a = i;
      return 0;
    }
  }
  *a = BUCKET_MAX;
  return 0;
}

/* Rerolls and decrypts an UnrolledCipherText back into an integer from 0 to BUCKET_MAX */
int decrypt_and_reroll(unsigned char *a, const struct UnrolledCipherText uct, const struct PrivateKey priv_key) {
  struct UnrolledPlainText upt;
  for (int i=0; i<BUCKET_MAX; i++) {
    if (decrypt(&(upt.arr[i]), uct.arr[i], priv_key)!=0) {return -1;}
  }
  if (reroll(a, upt) != 0) {return -1;};
  return 0;
}

/* Rerolls and decrypts an UnrolledCipherText back into an integer from 0 to BUCKET_MAX */
int decrypt_and_reroll_with_sec(unsigned char *a, const struct UnrolledCipherText uct, const struct UnrolledSharedSecret uss) {
  struct UnrolledPlainText upt;
  for (int i=0; i<BUCKET_MAX; i++) {
    if (decrypt_with_sec(&(upt.arr[i]), uct.arr[i], uss.arr[i])!=0) {return -1;}
  }
  if (reroll(a, upt) != 0) {return -1;};
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
  return 0; }

int encrypt_buckets(unsigned char *out, const unsigned char *in, const struct PublicKey pubkey, const unsigned int max_buckets) {
  unsigned int i = 0;
  struct UnrolledCipherText uval;
  //struct CipherText cval;
  while (in[i] != 255) {
    if (unroll_and_encrypt(&uval, in[i], pubkey)!=0) { return -1;}
    memcpy(&out[i*(sizeof uval.arr)], uval.arr, sizeof uval.arr);
    if (i++>max_buckets) {
      error_print("ERROR: too many elements for size of array: %i\n", i);
      return -2;
    }
  }
  return (int)i;
}

int decrypt_buckets(unsigned char *plain, const unsigned char *enc, const struct PrivateKey privkey, const unsigned int num_elem) {
  unsigned int i = 0;
  //struct PlainText uval;
  //struct CipherText cval;
  unsigned char x;
  struct UnrolledCipherText uval;
  for (i=0; i<num_elem; i++) {
    memcpy(uval.arr, &enc[i*(sizeof uval.arr)], sizeof uval.arr);
    if (decrypt_and_reroll(&x, uval, privkey)!=0) {
      error_print("ERROR: could not decrypt values\n");
      return -1;
    }
    plain[i] = x;
    //error_print("%i\n", plain[i]);
  }
  plain[num_elem] = 0;
  return (int)num_elem;
}

int decrypt_buckets_with_sec(unsigned char *plain, const unsigned char *enc, const unsigned char *shared_sec, const unsigned int num_elem) {
  unsigned int i = 0;
  //struct PlainText uval;
  //struct CipherText cval;
  unsigned char x;
  struct UnrolledCipherText uval;
  struct UnrolledSharedSecret uss;
  for (i=0; i<num_elem; i++) {
    memcpy(uval.arr, &enc[i*(sizeof uval.arr)], sizeof uval.arr);
    memcpy(uss.arr, &shared_sec[i*(sizeof uss.arr)], sizeof uss.arr);
    if (decrypt_and_reroll_with_sec(&x, uval, uss)!=0) {
      error_print("ERROR: could not decrypt values\n");
      return -1;
    }
    plain[i] = x;
    //error_print("%i\n", plain[i]);
  }
  plain[num_elem] = 0;
  return (int)num_elem;
}


int read_file_to_array(unsigned char *ans, char *fn, size_t buf_size) {
  FILE * fp = fopen(fn, "r");
  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  intmax_t val = 0;
  if (fp) {
    int i = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
      val = strtoimax(line, NULL, 10);
      if ((val >= 0) && (val <= BUCKET_MAX)) {
        ans[i++] = val;
      } else {
        error_print("ERROR: value on line %i not a number in [1, BUCKET_MAX].\n", i);
        return -1;
      }
      if (i > (int)buf_size) {
        error_print("ERROR: exceeded maximum number of lines: %lu.\n", buf_size);
        return -1;
      }
    }
    info_print("INFO: Read %i lines.\n", i);
    fclose(fp);
    ans[i] = 255;
    return i;
  } else {
    error_print("ERROR: could not open %s for reading.\n", fn);
    return -1;
  }
}

int read_partial_decryption_file(unsigned char *ans, char *fn, int buf_size) {
  FILE *fp = fopen(fn, "rb");
  ssize_t size;
  size_t read;
  int num_ss;
  if (fp) {
    fseek (fp , 0 , SEEK_END);
    size = ftell (fp);
    rewind (fp);
    if (size % (crypto_core_ristretto255_BYTES) != 0) {
      error_print("ERROR: %s contains %ld bytes, which does not divide %i.\n", fn, size, 2*crypto_core_ristretto255_BYTES);
      fclose(fp);
      return -1;
    } else if (size > buf_size) {
      error_print("ERROR: %s contains %lu bytes, which is larger than the buffer size: %i.\n", fn, size, buf_size);
      fclose(fp);
      return -1;
    } else if (size < 0) {
      error_print("ERROR: problems opening %s for reading.\n", fn);
      fclose(fp);
      return -1;
    }
    read = fread(ans, 1, (size_t)size, fp);
    num_ss = read / (crypto_core_ristretto255_BYTES) ;
    info_print("INFO: successfully read %ld bytes from %s, ~%i SharedSecrets.\n", read, fn, num_ss);
    fclose(fp);
    return num_ss;
  } else {
    error_print("ERROR: could not open %s for reading.\n", fn);
    return -1;
  }

}

int read_binary_CipherText_file(unsigned char *ans, char *fn, int buf_size) {
  FILE *fp = fopen(fn, "rb");
  //char buffer[max_CipherText_num * 2 * crypto_core_ristretto255_BYTES];
  ssize_t size;
  size_t read;
  int num_ciphertexts;
  if (fp) {
    //int i = 0;
    fseek (fp , 0 , SEEK_END);
    size = ftell (fp);
    rewind (fp);
    if (size % (2*crypto_core_ristretto255_BYTES) != 0) {
      error_print("ERROR: %s contains %ld bytes, which does not divide %i.\n", fn, size, 2*crypto_core_ristretto255_BYTES);
      fclose(fp);
      return -1;
    } else if (size > buf_size) {
      error_print("ERROR: %s contains %lu bytes, which is larger than the buffer size: %i.\n", fn, size, buf_size);
      fclose(fp);
      return -1;
    } else if (size < 0) {
      error_print("ERROR: problems opening %s for reading.\n", fn);
      fclose(fp);
      return -1;
    }
    read = fread(ans, 1, (size_t)size, fp);
    num_ciphertexts = read / (2*crypto_core_ristretto255_BYTES) ;
    info_print("INFO: successfully read %ld bytes from %s, ~%i CipherTexts.\n", read, fn, num_ciphertexts);
    fclose(fp);
    return num_ciphertexts;
  } else {
    error_print("ERROR: could not open %s for reading.\n", fn);
    return -1;
  }

}

// Attention: GOTO used for cleanup
int encrypt_bucket_file(char *key_fn, char *input_fn, char *output_fn) {
  unsigned int uct_size = sizeof (((struct UnrolledCipherText*)0)->arr);
  int return_val = 0;
  struct PublicKey pub_key;
  unsigned int size_of_array = 0;
  if (read_pubkey(&pub_key, key_fn)!=0) {return_val = -1; goto cleanup; }
  unsigned char byte_array[BUCKET_NUM];
  memset(byte_array, 0, sizeof byte_array);
  int tmp = read_file_to_array(byte_array, input_fn, sizeof byte_array);
  if (tmp < 0) {
    error_print("ERROR: could not read file into array.\n");
    return_val = tmp;
    goto cleanup;
  } else {
    size_of_array = (unsigned int)tmp;
  }
  unsigned char *out_array;
  unsigned int size_of_out_array = size_of_array*uct_size;
  info_print("INFO: allocating %u bytes\n", size_of_out_array);
  out_array = (unsigned char *)malloc(size_of_out_array);
  if ((tmp = encrypt_buckets(out_array, byte_array, pub_key, sizeof byte_array) < 0)){
    error_print("ERROR: could not encrypt array.\n");
    return_val = tmp;
    goto cleanup;
  }
  FILE *out_file = fopen(output_fn, "wb");
  size_t bytes_written = 0;
  if (out_file) {
    bytes_written = fwrite(out_array, 1, size_of_out_array, out_file);
    if (bytes_written != size_of_out_array) {
      error_print("ERROR: incorrect number of bytes written to %s.\n", output_fn);
      return_val = -5;
      goto cleanup;
    }
    info_print("INFO: Written %lu bytes to %s.\n", bytes_written, output_fn);
    fclose(out_file);
    return_val = 0;
    goto cleanup;
  } else {
    error_print("ERROR: could not open %s for writing.\n", output_fn);
    return_val = -6;
    goto cleanup;
  }

  cleanup:
  if (out_array != NULL) {
    free(out_array);
  }
  return return_val;

}

int decrypt_bucket_file(char *key_fn, char *input_fn, char *output_fn) {
  int return_val = 0;
  unsigned int uct_size = sizeof (((struct UnrolledCipherText*)0)->arr);
  struct PrivateKey priv_key;
  int tmp;
  unsigned int size_of_array = 0;
  if ((tmp = read_privkey(&priv_key, key_fn)!=0)) {return tmp; }
  // unsigned char byte_array[BUCKET_NUM*crypto_core_ristretto255_BYTES*2];
  unsigned int max_byte_array_mem = BUCKET_NUM*uct_size;
  unsigned char *byte_array = malloc(max_byte_array_mem);
  memset(byte_array, 0, max_byte_array_mem);
  tmp = read_binary_CipherText_file(byte_array, input_fn, (int)max_byte_array_mem);
  if (tmp < 0) {
    error_print("ERROR: could not read file into array.\n");
    return_val = tmp;
    goto cleanup;
  } else {
    size_of_array = (unsigned int)tmp;
  }
  if (size_of_array % BUCKET_MAX != 0) {
    error_print("ERROR: size of array (%u) doesn't divide BUCKET_MAX (%u)\n", size_of_array, BUCKET_MAX);
    return -1;
  }
  unsigned int num_elem = size_of_array / BUCKET_MAX;
  info_print("INFO: decrypting %u ciphertexts\n", num_elem);
  unsigned char out_array[BUCKET_NUM];
  if ((tmp = decrypt_buckets(out_array, byte_array, priv_key, num_elem))<0){
    return_val = tmp; 
    goto cleanup;
  }
  FILE *out_file = fopen(output_fn, "w");
  if (out_file) {
    for (unsigned int i=0; i<num_elem; i++) {
      fprintf(out_file, "%i\n", out_array[i]);
    }
    info_print("INFO: Written %d lines to %s.\n", num_elem, output_fn);
    fclose(out_file);
    return_val = 0;
    goto cleanup;
  } else {
    error_print("ERROR: could not open %s for writing.\n", output_fn);
    return_val = -6;
    goto cleanup;
  }

  cleanup:
  if (byte_array != NULL) {
    free(byte_array);
  }
  return return_val;
}

int decrypt_bucket_file_with_sec(char *shared_sec_fn, char *input_fn, char *output_fn) {
  int return_val = 0;
  unsigned int uct_size = sizeof (((struct UnrolledCipherText*)0)->arr);
  unsigned int uss_size = sizeof (((struct UnrolledSharedSecret*)0)->arr);
  int tmp;
  unsigned int size_of_array = 0;

  unsigned int max_byte_array_mem = BUCKET_NUM*uct_size;
  unsigned char *byte_array = malloc(max_byte_array_mem);
  unsigned char *sec_array = malloc(max_byte_array_mem);

  memset(byte_array, 0, max_byte_array_mem);
  tmp = read_binary_CipherText_file(byte_array, input_fn, (int)max_byte_array_mem);
  if (tmp < 0) {
    error_print("ERROR: could not read file into array.\n");
    return_val = tmp;
    goto cleanup;
  } else {
    size_of_array = (unsigned int)tmp;
  }
  if (size_of_array % BUCKET_MAX != 0) {
    error_print("ERROR: size of array (%u) doesn't divide BUCKET_MAX (%u)\n", size_of_array, BUCKET_MAX);
    return_val = -1;
    goto cleanup;
  }
  unsigned int num_elem = size_of_array / BUCKET_MAX;
  info_print("INFO: decrypting %u ciphertexts\n", num_elem);

  tmp = read_partial_decryption_file(sec_array, shared_sec_fn, (int)max_byte_array_mem);
  if (tmp < 0) {
    error_print("ERROR: could not read secrets file into array.\n");
    return_val = tmp;
    goto cleanup;
  }
  if (tmp / BUCKET_MAX != (int)num_elem) {
    error_print("ERROR: number of ciphertexts (%u) must equal number of shared secrets (%u)\n", num_elem, tmp/(int)uss_size);
    return_val = -1;
    goto cleanup;
  }

  unsigned char out_array[BUCKET_NUM];
  if ((tmp = decrypt_buckets_with_sec(out_array, byte_array, sec_array, num_elem))<0){
    return_val = tmp; 
    goto cleanup;
  }
  FILE *out_file = fopen(output_fn, "w");
  if (out_file) {
    for (unsigned int i=0; i<num_elem; i++) {
      fprintf(out_file, "%i\n", out_array[i]);
    }
    info_print("INFO: Written %d lines to %s.\n", num_elem, output_fn);
    fclose(out_file);
    return_val = 0;
    goto cleanup;
  } else {
    error_print("ERROR: could not open %s for writing.\n", output_fn);
    return_val = -6;
    goto cleanup;
  }

  cleanup:
  if (byte_array != NULL) {
    free(byte_array);
  }
  if (sec_array != NULL) {
    free(sec_array);
  }
  return return_val;
}

int get_partial_decryptions(char *key_fn, char *input_fn, char *output_fn) {
  int return_val = 0;
  struct PrivateKey priv_key;
  int tmp;
  unsigned int size_of_array = 0;
  if ((tmp = read_privkey(&priv_key, key_fn)!=0)) {return tmp; }

  ssize_t size;
  size_t bytes_read = 0;
  FILE *fp =fopen(input_fn, "rb");
  unsigned char *in_array;
  if (fp) {
    fseek (fp , 0 , SEEK_END);
    size = ftell (fp);
    rewind (fp);
    if (size % (2*crypto_core_ristretto255_BYTES) != 0) {
      error_print("ERROR: %s contains %ld bytes, which does not divide %i.\n", input_fn, size, 2*crypto_core_ristretto255_BYTES);
      fclose(fp);
      return -1;
    }
    in_array = (unsigned char *)malloc((size_t)size);
    bytes_read = fread(in_array, 1, (size_t)size, fp);
    fclose(fp);
  }

  unsigned char *out_array = (unsigned char*)malloc((size_t)size/2);
  struct SharedSecret s;
  struct CipherText x;
  for (int i=0; i< size/(2*crypto_core_ristretto255_BYTES); i++) {
    memcpy(x.c1, &in_array[2*i*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(x.c2, &in_array[(2*i+1)*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    if (shared_secret(&s, x, priv_key)!=0) {
      return_val = -1;
      goto cleanup;
    }
    memcpy(&out_array[i*crypto_core_ristretto255_BYTES], s.val, crypto_core_ristretto255_BYTES);
  }

  size_t bytes_written = 0;
  fp = fopen(output_fn, "wb");
  if (fp) {
    bytes_written = fwrite(out_array, 1, (size_t)size/2, fp);
    fclose(fp);
  }
  if ((ssize_t)bytes_written != size/2) {
    error_print("ERROR: incorrect number of bytes written to %s.\n", output_fn);
    return_val = -5;
    goto cleanup;
  } else {
    info_print("INFO: Written %lu bytes to %s.\n", bytes_written, output_fn);
    return_val = 0;
    goto cleanup;
  }

  cleanup:
  free(in_array);
  free(out_array);
  return return_val;
}

int add_all_ciphertexts(unsigned char *a1, const unsigned char *a2, const int num_elem) {
  struct CipherText x;
  struct CipherText y;
  struct CipherText z;
  for (int i=0; i<num_elem; i++) {
    memcpy(x.c1, &a1[2*i*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(x.c2, &a1[(2*i+1)*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(y.c1, &a2[2*i*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(y.c2, &a2[(2*i+1)*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    if (add_ciphertext(&z, x, y)!=0) {
      error_print("ERROR: addition failure. 39fjs:%i\n", i);
      return -1;
    }
    memcpy(&a1[2*i*crypto_core_ristretto255_BYTES], z.c1, crypto_core_ristretto255_BYTES);
    memcpy(&a1[(2*i+1)*crypto_core_ristretto255_BYTES], z.c2, crypto_core_ristretto255_BYTES);
  }
  return 0;
}

int add_all_secrets(unsigned char *a1, const unsigned char *a2, const int num_elem) {
  struct SharedSecret x;
  struct SharedSecret y;
  struct SharedSecret z;
  for (int i=0; i<num_elem; i++) {
    memcpy(x.val, &a1[i*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    memcpy(y.val, &a2[i*crypto_core_ristretto255_BYTES], crypto_core_ristretto255_BYTES);
    if (crypto_core_ristretto255_add(z.val, x.val, y.val)!=0) {
      error_print("ERROR: addition failure. 854sj:%i\n", i);
      return -1;
    }
    memcpy(&a1[i*crypto_core_ristretto255_BYTES], z.val, crypto_core_ristretto255_BYTES);
  }
  return 0;
}

/*int array_max_in_place(unsigned char *a1, const unsigned char *a2, const int num_array_elements) {
  return add_all_ciphertexts(a1, a2, num_array_elements*BUCKET_MAX);
}*/

int combine_binary_CipherText_files(char *combined_fn, char **fns, const int ncount) {
  unsigned int cipher_size = 2*crypto_core_ristretto255_BYTES;
  FILE *combined_file = fopen(combined_fn, "rb");
  if (combined_file) {
    error_print("ERROR: %s exists.\nAborting so we don't clobber it.\n", combined_fn);
    fclose(combined_file);
    return -2;
  }

  ssize_t size;
  FILE *fp = fopen(fns[0], "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fclose(fp);
  } else {
    error_print("ERROR: problems opening %s for reading.\n", fns[0]);
    return -1;
  }
  if (size < 0) {
    error_print("ERROR: problems seeking end of %s.\n", fns[0]);
    return -1;
  } else if (size % cipher_size != 0) {
    error_print("ERROR: %s contains %ld bytes, which does not divide %i.\n", fns[0], size, cipher_size);
    return -1;
  }
  unsigned int num_ciphertext = size / cipher_size;
  

  int return_val = 0;
  //unsigned char buffer[crypto_core_ristretto255_BYTES + 1];
  unsigned char *ans;
  ans = calloc((size_t)size, 1);
  unsigned char *buffer;
  buffer = calloc((size_t)size, 1);

  for (int file_it=0; file_it<ncount; file_it++) {
    if (read_binary_CipherText_file(buffer, fns[file_it], (int)num_ciphertext*(int)cipher_size)==(int)num_ciphertext) {
      if (file_it == 0) {
        memcpy(ans, buffer, (size_t)size);
      } else if (add_all_ciphertexts(ans, buffer, (int)num_ciphertext)!=0) {
        error_print("ERROR: something wrong happened. 21f2s3\n");
        return_val = -1;
        goto cleanup;
      }
    } else {
      error_print("ERROR: %s is not the right size\n", fns[file_it]);
      return_val = -1;
      goto cleanup;
    }
  }

  // writing combined buffer now

  size_t bytes_written;
  combined_file = fopen(combined_fn, "wb");
  if (combined_file) {
    bytes_written = fwrite(ans, 1, (size_t)size, combined_file);
    if (bytes_written != (size_t)size) {
      error_print("ERROR: incorrect number of bytes written to %s.\n", combined_fn);
      return_val = -1;
      goto cleanup;
    }
  } else {
    error_print("ERROR: problem writing %s.\n", combined_fn);
    return_val = -1;
    goto cleanup;
  }
  info_print("INFO: successfully written to %s.\n", combined_fn);

  cleanup:
  free(ans);
  free(buffer);
  return return_val;
}

int combine_partial_decryptions(char *combined_fn, char **fns, const int ncount) {
  unsigned int ss_size = crypto_core_ristretto255_BYTES;
  FILE *combined_file = fopen(combined_fn, "rb");
  if (combined_file) {
    error_print("ERROR: %s exists.\nAborting so we don't clobber it.\n", combined_fn);
    fclose(combined_file);
    return -2;
  }

  ssize_t size;
  FILE *fp = fopen(fns[0], "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fclose(fp);
  } else {
    error_print("ERROR: problems opening %s for reading.\n", fns[0]);
    return -1;
  }
  if (size < 0) {
    error_print("ERROR: problems seeking end of %s.\n", fns[0]);
    return -1;
  } else if (size % ss_size != 0) {
    error_print("ERROR: %s contains %ld bytes, which does not divide %i.\n", fns[0], size, ss_size);
    return -1;
  }
  unsigned int num_secrets = size / ss_size;
  

  int return_val = 0;
  //unsigned char buffer[crypto_core_ristretto255_BYTES + 1];
  unsigned char *ans;
  ans = calloc((size_t)size, 1);
  unsigned char *buffer;
  buffer = calloc((size_t)size, 1);

  for (int file_it=0; file_it<ncount; file_it++) {
    if (read_partial_decryption_file(buffer, fns[file_it], (int)num_secrets*(int)ss_size)==(int)num_secrets) {
      if (file_it == 0) {
        memcpy(ans, buffer, (size_t)size);
      } else if (add_all_secrets(ans, buffer, (int)num_secrets)!=0) {
        error_print("ERROR: something wrong happened. i23dd\n");
        return_val = -1;
        goto cleanup;
      }
    } else {
      error_print("ERROR: %s is not the right size\n", fns[file_it]);
      return_val = -1;
      goto cleanup;
    }
  }

  // writing combined buffer now

  size_t bytes_written;
  combined_file = fopen(combined_fn, "wb");
  if (combined_file) {
    bytes_written = fwrite(ans, 1, (size_t)size, combined_file);
    if (bytes_written != (size_t)size) {
      error_print("ERROR: incorrect number of bytes written to %s.\n", combined_fn);
      return_val = -1;
      goto cleanup;
    }
  } else {
    error_print("ERROR: problem writing %s.\n", combined_fn);
    return_val = -1;
    goto cleanup;
  }
  info_print("INFO: successfully written to %s.\n", combined_fn);

  cleanup:
  free(ans);
  free(buffer);
  return return_val;
}

