#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../include/galoisu.h"

#define RIJNDAEL_POLY   0x1B
#define RIJNDAEL_POLY2  0x6C
#define RIJNDAEL_POLY4  0xAB
#define RIJNDAEL_POLY8  0x9A
#define POLY_VECTOR     0x63
#define POLY_VECTOR_INV 0x05
#define BYTE_ROL(x, s)  (((x) << (s)) | ((x) >> (8 - s)))

uint8_t
gmulu(uint8_t a, uint8_t b)
{
	uint8_t c;
	int i;

	for (i = 0, c = 0; i < 8; i++) {
		if ((b & 1) != 0)
			c ^= a;
		b >>= 1;
		if ((a & 0x80) != 0)
			a = (a << 1) ^ RIJNDAEL_POLY;
		else
			a <<= 1;
	}

	return c;
}

/* Возвращает a^2 в поле Rijndael                                   */
/* Занимает примерно столько же времени, сколько половина умножения */
static uint8_t
gsquareu(uint8_t a)
{
	uint8_t p;

	p = (a & 0x01) ^ ((a & 0x02) << 1) ^
	        ((a & 0x04) << 2) ^ ((a & 0x08) << 3);
	if ((a & 0x10) != 0)
		p ^= RIJNDAEL_POLY;
	if ((a & 0x20) != 0)
		p ^= RIJNDAEL_POLY2;
	if ((a & 0x40) != 0)
		p ^= RIJNDAEL_POLY4;
	if ((a & 0x80) != 0)
		p ^= RIJNDAEL_POLY8;

	return p;
}

/* Возвращает a^254 */
static uint8_t
ginvu(uint8_t a)
{
	uint8_t b;
	uint8_t c;
	int i;

	/* a^254 = a^2 * a^4 * a^8 * a^16 * a^32 * a^64 * a^128 */
	/* 6 умножений и 7 возведений в квадрат = 9.5 умножений */
	b = gsquareu(a);
	c = b;
	for (i = 0; i < 6; i++) {
		b = gsquareu(b);
		c = gmulu(b, c);
	}

	return c;
}

uint8_t
transform_bitsu(uint8_t a)
{
	uint8_t b;

	b = ginvu(a);

	return b ^ BYTE_ROL(b, 1) ^ BYTE_ROL(b, 2) ^
	        BYTE_ROL(b, 3) ^ BYTE_ROL(b, 4) ^ POLY_VECTOR;
}

uint8_t
inv_transform_bitsu(uint8_t u)
{
	return ginvu(BYTE_ROL(u, 1) ^ BYTE_ROL(u, 3) ^ BYTE_ROL(u, 6) ^
	        POLY_VECTOR_INV);
}

/* Умножает каждый байт массива на 2 в поле Rijndael */
void
g2times(uint8_t *p, size_t n)
{
	int i;

	for (i = 0; i < n; i++)
		if ((p[i] & 0x80) != 0)
			p[i] = (p[i] << 1) ^ RIJNDAEL_POLY;
		else
			p[i] <<= 1;
}
