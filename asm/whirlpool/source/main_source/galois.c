#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../include/whirlpool_slow.h"
#define WHIRLPOOL_POLY	0x1d
#define WHIRLPOOL_GEN_POLY	0x02

static uint8_t exptab[256];
static uint8_t logtab[256];
uint8_t sbox[256];
const uint8_t rbox[16]  = {0x7,0xc,0xb,0xd,0xe,0x4,0x9,0xf,
  			  0x6,0x3,0x8,0xa,0x2,0x5,0x1,0x0};
const uint8_t ebox[16]  = {0x1,0xb,0x9,0xc,0xd,0x6,0xf,0x3,
  			  0xe,0x8,0x7,0x4,0xa,0x2,0x5,0x0};
const uint8_t iebox[16] = {0xF,0x0,0xD,0x7,0xB,0xE,0x5,0xA,
  			  0x9,0x2,0xC,0x1,0x3,0x4,0x8,0x6};
static
uint8_t gmul_slow(uint8_t a, uint8_t b) {

	int high_bit_on;
	uint8_t c = 0;

	while (b) {

		if (b & 0x1)
			c ^= a;

		high_bit_on = a & 0x80;
		a <<= 1;

		if (high_bit_on)
			a ^= WHIRLPOOL_POLY;
		b >>= 1;
	}

	return c;
}


void mix_rows_slow(uint32_t state[16])
{
	uint8_t *s0, *s1, *s2, *s3, *s4, *s5, *s6, *s7;
	uint8_t a0, a1, a2, a3, a4, a5, a6, a7;
	int i;

	s0 = (uint8_t *) state;
	s1 = (uint8_t *) state + 1;
	s2 = (uint8_t *) state + 2;
	s3 = (uint8_t *) state + 3;
	s4 = (uint8_t *) state + 4;
	s5 = (uint8_t *) state + 5;
	s6 = (uint8_t *) state + 6;
	s7 = (uint8_t *) state + 7;

	for (i = 0; i < 8; i++) {
		a0 = *s0 ^ gmul_slow(*s1, 0x09) ^ gmul_slow(*s2, 0x02) ^ gmul_slow(*s3, 0x05) ^
		 gmul_slow(*s4, 0x08) ^ *s5 ^ gmul_slow(*s6, 0x04) ^ *s7;
		a1 = *s0 ^ *s1 ^ gmul_slow(*s2, 0x09) ^ gmul_slow(*s3, 0x02) ^
		 gmul_slow(*s4, 0x05) ^ gmul_slow(*s5, 0x08) ^ *s6 ^ gmul_slow(*s7, 0x04);
		a2 = gmul_slow(*s0, 0x04) ^ *s1 ^ *s2 ^ gmul_slow(*s3, 0x09) ^
		 gmul_slow(*s4, 0x02) ^ gmul_slow(*s5, 0x05) ^ gmul_slow(*s6, 0x08) ^ *s7;
		a3 = *s0 ^ gmul_slow(*s1, 0x04) ^ *s2 ^ *s3 ^
		 gmul_slow(*s4, 0x09) ^ gmul_slow(*s5, 0x02) ^ gmul_slow(*s6, 0x05) ^ gmul_slow(*s7, 0x08);
		a4 = gmul_slow(*s0, 0x08) ^ *s1 ^ gmul_slow(*s2, 0x04) ^ *s3 ^
		 *s4 ^ gmul_slow(*s5, 0x09) ^ gmul_slow(*s6, 0x02) ^ gmul_slow(*s7, 0x05);
		a5 = gmul_slow(*s0, 0x05) ^ gmul_slow(*s1, 0x08) ^ *s2 ^ gmul_slow(*s3, 0x04) ^
		 *s4 ^ *s5 ^ gmul_slow(*s6, 0x09) ^ gmul_slow(*s7, 0x02);
		a6 = gmul_slow(*s0, 0x02) ^ gmul_slow(*s1, 0x05) ^ gmul_slow(*s2, 0x08) ^ *s3 ^
		 gmul_slow(*s4, 0x04) ^ *s5 ^ *s6 ^ gmul_slow(*s7, 0x09);
		a7 = gmul_slow(*s0, 0x09) ^ gmul_slow(*s1, 0x02) ^ gmul_slow(*s2, 0x05) ^ gmul_slow(*s3, 0x08) ^
		 *s4 ^ gmul_slow(*s5, 0x04) ^ *s6 ^ *s7;

		*s0 = a0; *s1 = a1; *s2 = a2; *s3 = a3;
		*s4 = a4; *s5 = a5; *s6 = a6; *s7 = a7;

		s0 += 8; s1 += 8; s2 += 8; s3 += 8;
		s4 += 8; s5 += 8; s6 += 8; s7 += 8;
	}
}

static
void galois_init_tables() {

	uint8_t c;
	int i;
	c = 1;

	for (i = 0; i < 256; i++) {
		logtab[c] = i;
		exptab[i] = c;
		c = gmul_slow(c, WHIRLPOOL_GEN_POLY);
	}
}

static
unsigned char transform_bits(uint8_t u){

	unsigned char x, y, r;

	x = ebox[u >> 4];
	y = iebox[u & 0x0f];
	r = rbox[x ^ y];

	return (ebox[x ^ r] << 4) | iebox[y ^ r];
}

static
void create_sbox() {

	int u;

	for(u = 0; u < 256; u++)  {
		sbox[u] = transform_bits(u);

	printf("%x ", sbox[u]);
	if(u % 16 == 0) printf("\n");
	}
}

void sub_bytes_slow(uint64_t state[8]) {

	uint8_t *temp = (uint8_t *) state;
	int i;

	for (i = 0; i < BLOCK_NBYTES; i++)
		temp[i] = transform_bits(temp[i]);

}


