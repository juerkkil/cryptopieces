/* Threefish-512 block cipher implementation in counter mode of operation - so this is
 * actually stream cipher. 
 * Written for TKK course T-79.4502 Cryptography and Data security
 * 2010, Jussi-Pekka Erkkilä <juerkkil@iki.fi>
 */

#include <string.h>
#include <stdio.h>
#include "threefish.h"

/* This function converts len*8 bytes of data to len integers */
void bytes_to_words(const unsigned char *bytes, unsigned long long int words[], int len) {
  unsigned long long int tmp = 0;
  /* Loop through len 8-bytes blocks */
  for(int i = 0; i < len; i++) {
    /* Loop though bytes one-by-one, shift tmp left by length of one byte
     * and add next byte to tmp. Note that we start each word from "end" 
     * because of "least-significant-byte-first convention" */
    for(int j = 7; j >= 0; j--) {
      tmp = tmp << 8;
      tmp += (unsigned long long int)(bytes[(i*8)+j]);
    }
    /* Now we have 8-byte word 'tmp' converted to long integer */
    words[i] = tmp;
    tmp = 0;
  }
}

/* inverse function for bytes_to_words.
 * Here also, notice the "least-significant-byte-first" -convention */
void words_to_bytes(unsigned char * bytes, unsigned long long int words[], int len) {
  unsigned char tmp = 0x00;
  for(int i = 0; i < len; i++) {
    for(int j = 0; j < 8; j++) {
      tmp = words[i] % 256;
      words[i]-= tmp;
      words[i] = words[i] >> 8;
      bytes[(i*8) + j] = tmp;
    }
  }
}

/* Permutation table, values are constants, copied from Skein specification */
int permutate (int i) {
  unsigned int permutation_table[] ={2, 1, 4, 7, 6, 5, 0, 3};
  return permutation_table[i];
}

/* Rotate table, values are constants, available in Skein specification */
int rotate(int d, int j) {
  unsigned int rotation_table[8][4] = {{46, 36, 19, 37}, {33, 27, 14, 42},
    {17, 49,36,39}, {44, 9, 54, 56}, {39, 30, 34, 24}, {13, 50, 10, 17},
    {25, 29, 39, 43}, {8, 35,56,22} };
  return rotation_table[d][j];
}

/* Initialize counter mode and precompute subkey values */
void init(const unsigned char *k, const unsigned char *t, tctx *ctx) {
  /* init counter and "keystream cache" */
  ctx->counter = 0;
  ctx->cache_length = 0;
  /* converting key to 64-bit words (array keys). Array includes one extra
   * item at end of it, we need that in generating subkeys */
  unsigned long long int keys[WORDS + 1];
  bytes_to_words(k, keys, WORDS);

  /* Converting tweak to 64-bit words (array tweak) 
   * length is three, because we need to specify t_2 when generating subkeys */
  unsigned long long int tweak[3];
  bytes_to_words(t, tweak, 2);

  /* Now we're going to compute subkeys: 
   * at first we calculate "extra items" in key- and tweak-arrays. */
  keys[WORDS] = 6148914691236517205; // this is constant, (2^64) / 3

  keys[WORDS]= keys[WORDS]^ keys[0]^keys[1]^ keys[2]^ keys[3]^ keys[4]^ keys[5]^ keys[6]^ keys[7];
/*  for(int i = 0; i < 8; i++) { // XORring keys[8] with other items in keys[] 
    keys[WORDS] ^= keys[i];
  }*/
  
  tweak[2] = tweak[0] ^ tweak[1]; // t_2 = t_0 XOR t_1
  /* Loop through subkeys and generate them */
  for(int s = 0; s < ((18) + 1); s++) {

    /* Implementin here subkey-generating algorithm 
     * specified in Skein specs.
     * Variable type (unsigned long long int) limits numbers to 2^64
     * so we don't need to specify "modulo 2^64" manually.
     */

    // NOTE: here, s= "round", i = word number 
    for(int i = 0; i < WORDS; i++) {
      ctx->subkey[s][i] = keys[ (s+i) % (WORDS + 1)];
      if(i == (WORDS - 3)) {
        ctx->subkey[s][i] += tweak[s % 3];
      } else if(i == (WORDS - 2)) {
        ctx->subkey[s][i] += tweak[(s+1) % 3];
      } else if(i == (WORDS - 1)) {
        ctx->subkey[s][i] += s;
      }
    }
  }
}

// using context ctx, encrypt len bytes of plaintext p and store the result in b.
void crypt(unsigned char *b, unsigned char *p, int len, tctx *ctx) {
  
  /* Initialize "words" for counter-mode message. We assume here, that max number
   * for counter is 2^64, so we need to increment only first item of encryption_msg[] 
   * every round. All other items [1,7] are zeroes.
   * This won't be problem as 2^64 * 64 bytes is 1073741824 Terabytes.
   */

  unsigned long long int encryption_msg[WORDS]; 
  for(int i = 0; i < 8; i++) encryption_msg[i] = 0;

  int rounds = 0;
  
  /* Calculate how many blocks of keystream we need to generate */
  if(len > ctx->cache_length) {
    if(len - ctx->cache_length == BLOCKSIZE) 
      rounds = 1;
    else
      rounds = ( (len - ctx->cache_length) - ((len - ctx->cache_length) % 64)   )/BLOCKSIZE + 1;
  }
  /* Allocate needed keystream and temporary array for cipher block */
  unsigned char keystream[rounds * BLOCKSIZE + ctx->cache_length];
  unsigned char tmp[BLOCKSIZE];

  /* Copy keystream_cache to keystream. Keystream cache includes the "extra-keystream"
   * which was left unused on previous crypt() -call. */
  for(int i = 0; i < ctx->cache_length; i++) {
    keystream[i]= ctx->keystream_cache[i];
  }

  /* Single cycle of this loop  generates 64 bytes of keystream and increases 
   * counter by one. Run as many times as needed to provide enough keystream */
  for(int i = 0; i < rounds; i++) {
    encryption_msg[0]= ctx->counter;
    encrypt_block(encryption_msg, ctx);
    /* Convert cipher block to bytes */
    words_to_bytes(tmp, encryption_msg, WORDS);

    /* Add generated cipher block to the end of keystream */
    for(int j = 0; j < BLOCKSIZE; j++) {
      keystream[i*BLOCKSIZE + j + ctx->cache_length] = tmp[j];  
    }
    ctx->counter++; 
  }
  /* Encrypt plain text with keystream. This implements the "stream cipher". */
  for(int i = 0; i < len; i++) {
    b[i] = keystream[i] ^ p[i];
  }
  /* Calculate how much keystream was left unused and save that to cache for next time */
  ctx->cache_length = (rounds*BLOCKSIZE+ctx->cache_length)-len;
  for(int i = 0; i < ctx->cache_length; i++) {
    ctx->keystream_cache[i] = keystream[i+len];
  }
}


/* Mix function, array y is "return value" */
void mix(unsigned long long int x0, unsigned long long int x1, int d, int j, unsigned long long int * y) {
  y[0] = x0 + x1;
  int shift = rotate((d % 8), j);
  // rotate-left: 
  y[1] = ((x1 << shift) | (x1 >> ( (sizeof(unsigned long long int)*8) - shift))) ^ y[0];
}

/* Single block encryption */
void encrypt_block(unsigned long long int *v, tctx *ctx) {
  /* Init variables / arrays needed on this operation */
  unsigned long long int e[WORDS];
  unsigned long long int f[WORDS];
  unsigned long long int tmp[2];

  /* Main loops which goes through rounds 0...72 */
  for(int d = 0; d < ROUNDS; d++) {
    /* If d mod 4 = 0, add subkey */
    if(d % 4 == 0) { 
      for(int i = 0; i < WORDS; i++) { 
        e[i] = v[i] + ctx->subkey[d/4][i];
      }
    } else {
      for(int i=0;i<WORDS;i++ ) 
        e[i]=v[i];
    }

    /* Mixing */
    for(int j = 0; j < WORDS/2; j++) {
      mix(e[j*2], e[j*2+1], d, j, tmp); // "return value" of mix() will be stored to tmp
      f[2*j] = tmp[0];
      f[2*j + 1] = tmp[1];
    }
    /* Implementing permutation */
 /*   for(int i = 0; i < WORDS; i++) {
      v[i] = f[permutate(i)];
    }*/
    v[0]= f[2];
    v[1]= f[1];
    v[2]= f[4];
    v[3]= f[7];
    v[4]= f[6];
    v[5]= f[5];
    v[6]= f[0];
    v[7]= f[3];
  }
  /* Finalize */
  /*for(int i=0; i < WORDS; i++) {
    v[i] = v[i] + ctx->subkey[18][i];
  }*/
    v[0] = v[0] + ctx->subkey[18][0];
    v[1] = v[1] + ctx->subkey[18][1];
    v[2] = v[2] + ctx->subkey[18][2];
    v[3] = v[3] + ctx->subkey[18][3];
    v[4] = v[4] + ctx->subkey[18][4];
    v[5] = v[5] + ctx->subkey[18][5];
    v[6] = v[6] + ctx->subkey[18][6];
    v[7] = v[7] + ctx->subkey[18][7];
  /* Now v[] includes encrypted block */
}



