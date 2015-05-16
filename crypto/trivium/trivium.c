/* Trivium stream cipher software implementation, quite poor performance.
 * Written for TKK course T-79.4502 Cryptograhy and Data security 
 * 2010, Jussi-Pekka Erkkilä <juerkkil@iki.fi>
 */

#include <string.h>
#include <stdio.h>
#include "trivium.h"

/* Return value of single bit in char array */
char bit_value(unsigned char *str, int bit_number) {
  return (str[bit_number/8] & (1 << bit_number%8)) >> (bit_number%8);
}
/* Set value of single bit in char array, either 0 or 1 (variable state) */
void set_bit (unsigned char * str, int bit_number, int state) {
  if(state)
    str[bit_number/8] |= 1 << (bit_number%8);
  else
    str[bit_number/8] &= ~(1 << (bit_number%8));
}
/*
  initialize the cipher with key k and iv; ctx is the state.
*/
void init(unsigned char *k, unsigned char *iv, sctx *ctx) {

  char t;
  int j = 0;
  char t1, t2, t3; 
  memset(ctx->state, 0, 36); 

  /* Build initial state bits one-by-one */
  for(int i = 0; i < 288; i++) {
    if(i < 80) { /* First 80 bits, copy key*/
      if(bit_value(k, 79-i))
        ctx->state[i/8] |= 1 << (i%8);
      else 
        ctx->state[i/8] &= ~(1 << (i%8));
    } else if(i >= 93 && i < 173) { /* Next 80 bits, copy initial vector */
      if(bit_value(iv, 79 - (i - 93)))
        ctx->state[i/8] |= 1 << (i%8);
      else
        ctx->state[i/8] &= ~(1 << (i%8));
    }
    else if(i > 284) { /* Mark last three to 1 */
      ctx->state[35] |= 1 << (i%8);
    } else { /* And rest of the bits to zero */
      ctx->state[i/8] &= ~(1 << (i%8));
    }
  }

  for(int i = 0; i < 1152; i++) {

    /* Save values t1, t2, t3 before shifting the initial state */
    /* t1 = s_66 + s_91 * s_92 + s_93 + s_171 */
    t1 = bit_value(ctx->state, 65) ^ bit_value(ctx->state, 90) & 
        bit_value(ctx->state, 91) ^ bit_value(ctx->state, 92) ^
        bit_value(ctx->state, 170);

    /* t2 = s_162 + s_175 * s_176 + s_177 + s_264 */
    t2 = bit_value(ctx->state, 161) ^ bit_value(ctx->state, 174) & 
        bit_value(ctx->state, 175) ^ bit_value(ctx->state, 176) ^
        bit_value(ctx->state, 263);

    /* t3 = s_243 + s_286 * s_287 + s_288 + s_69 */
    t3 =  bit_value(ctx->state, 242) ^ bit_value(ctx->state, 285) & 
        bit_value(ctx->state, 286) ^ bit_value(ctx->state, 287) ^
        bit_value(ctx->state, 68);

    /* Shift intial state one bit left */
    for(int j = 35; j >= 0; j--) {
      /* Shift every byte one-by-opne */
      ctx->state[j] = ctx->state[j] << 1;
      if(j > 0) {
        /* Keep sequential bytes synchronized */
        if(ctx->state[j-1] & (1 << 7))
          ctx->state[j] |= 1;
      }
    }
    /* set first bit to t3 */
    if(t3) 
      ctx->state[0] |= 1; // set first bit of the byte
    else
      ctx->state[0] &= ~1;
    /* set s_94 = t1 */
    if(t1) 
      ctx->state[11] |= 32; // set bit number 5
    else
      ctx->state[11] &= ~32; 
    /* set s_178 = t2 */
    if(t2) 
      ctx->state[22] |= 2; // set bit number 2
    else
      ctx->state[22] &= ~2; 
  }
}

/*
  encrypt/decrypt message m of length len into buffer b.
*/
void crypt(unsigned char *b, unsigned char *m, int len, sctx *ctx) {
  char t1, t2, t3;
  unsigned char tmp[len], tmp_state[288]; // temporary arrays for generating keystream
  memset(tmp, 0, len);
  unsigned int loops = 1 + (len / 8); // calculate how many 64-bit chunks we generate
  for(int i = 0; i < 280; i++) {
    tmp_state[i+8]= ctx->state[i];
  }
  for(int j = 0; j < loops; j++) {
    /* Shift state by 64 bits  */
    for(int i = 0; i < 280; i++) {
      tmp_state[i+8]= ctx->state[i];
    }
    for(int i = 0; i < 64; i++) {
      /* Save values t1, t2, t3 */
      /* t1 = s_66 + s_91 * s_92 + s_93 + s_171 */
      t1 = bit_value(ctx->state, 65 - i) ^ bit_value(ctx->state, 90 - i) & 
        bit_value(ctx->state, 91 - i) ^ bit_value(ctx->state, 92 - i) ^
        bit_value(ctx->state, 170 - i);

      /* t2 = s_162 + s_175 * s_176 + s_177 + s_264 */
      t2 = bit_value(ctx->state, 161 - i) ^ bit_value(ctx->state, 174-i) & 
        bit_value(ctx->state, 175-i) ^ bit_value(ctx->state, 176-i) ^
        bit_value(ctx->state, 263-i);

      /* t3 = s_243 + s_286 * s_287 + s_288 + s_69 */
      t3 =  bit_value(ctx->state, 242-i) ^ bit_value(ctx->state, 285-i) & 
        bit_value(ctx->state, 286-i) ^ bit_value(ctx->state, 287-i) ^
        bit_value(ctx->state, 68-i);

      /* Generate one bit of keystream and save it to array tmp */
      if( bit_value(ctx->state, 65-i) ^ bit_value(ctx->state, 92-i) ^ 
          bit_value(ctx->state, 242-i) ^ bit_value(ctx->state, 287-i) ^ 
          bit_value(ctx->state, 176-i) ^ bit_value(ctx->state, 161-i) ) {
        tmp[j*8 + i/8] |= 1 << (i%8);
      } else {
        tmp[j*8 + i/8] &= ~(1 << (i%8));
      }
      /* With t_3, t_2 and t_1 we generate new state for next 8-byte chunk of keystream */
      /* set s_1 = t_3 */
      if(t3) 
        set_bit(tmp_state, 63-i, 1);
      else
        set_bit(tmp_state, 63-i, 0);
      /* set s_94 = t1 */
      if(t1) 
        set_bit(tmp_state, 93+63-i, 1);
      else
        set_bit(tmp_state, 93+63-i, 0);
      /* set s_178 = t2 */
      if(t2) 
        set_bit(tmp_state, 177+63-i, 1);
      else
        set_bit(tmp_state, 177+63-i, 0);
    }
    /* Replace context state with temporary state: this adds 64-bit chunk of "fresh data */
    memcpy(ctx->state, tmp_state, 36);
  }
  /* After we've generated enough keystream, encrypt the data with XOR */
  for(int i = 0; i < len; i++) { 
    b[i] = m[i] ^ tmp[i];
  }

}

