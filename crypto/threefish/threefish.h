/* Threefish-512 block cipher implementation in counter mode of operation - so this is
 * actually stream cipher. 
 * Written for TKK course T-79.4502 Cryptography and Data security
 * 2010, Jussi-Pekka Erkkilä <juerkkil@iki.fi>
 */

#include <stdint.h>

/* Usage:
	tctx ctx;
	unsigned char plain[LEN], cipher[LEN], key[64], iv[16];
        // encrypted text will be saved to str cipher
	init(key, iv, &ctx);
	crypt(cipher, plain, LEN, &ctx);
 */

#define BLOCKSIZE 64 // block size is 64 bytes in Threefish-512 
#define ROUNDS 72 // N_r in specification
#define WORDS 8 // N_w in specification

typedef struct {
  unsigned long long int counter;
  unsigned char keystream_cache[BLOCKSIZE];
  int cache_length;
  unsigned long long int keys[8];
  unsigned long long int tweak[2];
  /* Specification says, there's N_r / 4 + 1 subkeys, each which of which
   * consists of N_w words. Here's corresponding array. */
  unsigned long long int subkey[(ROUNDS/4) + 1][WORDS];
} tctx;

void bytes_to_words(const unsigned char *, unsigned long long int[], int );
void words_to_bytes(unsigned char *, unsigned long long int[], int);
int permutate (int);
int rotate( int, int );
void crypt(unsigned char *, unsigned char *, int, tctx *);
void init(const unsigned char *, const unsigned char *, tctx *);
void mix(unsigned long long int, unsigned long long int, int, int, unsigned long long int * );
void encrypt_block(unsigned long long int *, tctx *);

