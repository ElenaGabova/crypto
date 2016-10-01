#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define GENERATING_POLY	0x03
#define RIJNDAEL_POLY	0x1b

#include "galois.h"

uint8_t gmul( uint8_t a, uint8_t b)
{
	int high_bit_on;
	 uint8_t c;

	c = 0;

	while (b) {

		if (b & 0x1)
			c ^= a;

		high_bit_on = a & 0x80;
		a <<= 1;

		if (high_bit_on)
			a ^= RIJNDAEL_POLY;
		b >>= 1;
	}

	return c;
}

