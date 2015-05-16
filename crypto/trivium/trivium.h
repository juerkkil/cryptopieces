#include <stdint.h>

/* usage:
	sctx ctx;
        unsigned char k[10], iv[10]; // set some values for key and initial vector ; key is secret!
	init(k, iv, &ctx);
	unsigned char ks[16]; // text to be secured
	crypt(ks, ks, 16, &ctx);

*/

typedef struct { 
  char state[36];
} sctx;

char bit_value(unsigned char *str, int bit_number);
void set_bit (unsigned char * str, int bit_number, int state);
void init(unsigned char *, unsigned char *, sctx *);
void crypt(unsigned char *, unsigned char *, int, sctx *);

