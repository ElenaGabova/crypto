#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../include/galois.h"


/*
 * AES operation MixColumns performs vector-matrix multiplication
 * of a state column bytes with a circular matrix cir(0x2, 0x3, 0x1, 0x1).
 * This property allows us to construct a table for this multiplication.
 */
#define P0(x) \
	(gmul((x), 0x2) | ((x) << 8) | ((x) << 16) | (gmul((x), 0x3) << 24))
#define P1(x) \
	(gmul((x), 0x3) | (gmul((x), 0x2) << 8) | ((x) << 16) | ((x) << 24))
#define P2(x) \
	((x) | (gmul((x), 0x3) << 8) | (gmul((x), 0x2) << 16) | ((x) << 24))
#define P3(x) \
	((x) | ((x) << 8) | (gmul((x), 0x3) << 16) | (gmul((x), 0x2) << 24))

/*
 * AES operation InvMixColumns performs vector-matrix multiplication
 * of a state column bytes with a circular matrix cir(0xe, 0x9, 0xd, 0xb) which
 * is the inverse with cir(0x2, 0x3, 0x1, 0x1), of course in GF(2^8).
 * Tables are constructed and used the same way as with MixColumns.
 */
#define Q0(x) \
	(gmul((x), 0xe) | (gmul((x), 0x9) << 8) | (gmul((x), 0xd) << 16) | (gmul((x), 0xb) << 24))
#define Q1(x) \
	(gmul((x), 0xb) | (gmul((x), 0xe) << 8) | (gmul((x), 0x9) << 16) | (gmul((x), 0xd) << 24))
#define Q2(x) \
	(gmul((x), 0xd) | (gmul((x), 0xb) << 8) | (gmul((x), 0xe) << 16) | (gmul((x), 0x9) << 24))
#define Q3(x) \
	(gmul((x), 0x9) | (gmul((x), 0xd) << 8) | (gmul((x), 0xb) << 16) | (gmul((x), 0xe) << 24))


#define GENERATING_POLY	0x03
#define RIJNDAEL_POLY	0x1b


#define POLY_VECTOR	0x63
#define BYTE_ROL(x)	((x << 1) | (x >> 7))




static uint32_t M0[256];
static uint32_t M1[256];
static uint32_t M2[256];
static uint32_t M3[256];

static uint32_t I0[256];
static uint32_t I1[256];
static uint32_t I2[256];
static uint32_t I3[256];

static uint8_t sbox[256];
static uint8_t inv_sbox[256];

/*Умножение многочленов в GF(2^8)*/
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

/*--------------------------------------------*/
/*Нахождение обратного элемента в GF(2^8)*/
unsigned char gmul_inv(unsigned char a)
{
 	unsigned char result;
 	int i = 0;

	result = a;

	 while(i < 253) {

	 	result = gmul(result, a);
	 	i++;
	 }

	 return(result);
}

/*--------------------------------------------*/
/*Вычисление нового значения байта*/
uint8_t transform_bits(uint8_t u) {
	unsigned short j;
	unsigned char x,y;

	x = gmul_inv((unsigned char)u);
	 y = x;

	 for(j=0; j < 4; j++) {
		 y = BYTE_ROL(y);
		 x ^= y;
	 }

	 x ^= POLY_VECTOR;

	 return x;
}


/*--------------------------------------------*/
/*Печать таблицы Sbox*/
void sbox_print() {
	int i, j;

	printf("static const uint8_t sbox[256] = {\n");

	for (i = 0; i < 256; i += 16) {
		printf("   ");
		for (j = i; j <	i+16; j++)
			printf("0x%02x, ",  sbox[j]);
		printf("\n");
	}

	printf("};\n");


	printf("static const uint8_t isbox[256] = {\n");

	for (i = 0; i < 256; i += 16) {
		printf("   ");
		for (j = i; j <	i+16; j++) {
			printf("0x%02x, ",  inv_sbox[j]);
		}
		printf("\n");
	}

	printf("};\n");

}



/*Создание таблиц для умножения*/
/*--------------------------------------------*/
void create_mix_tables()
{
	int x;

	for (x = 0; x < 256; x++) {
		M0[x] = P0(x);
		M1[x] = P1(x);
		M2[x] = P2(x);
		M3[x] = P3(x);
		I0[x] = Q0(x);
		I1[x] = Q1(x);
		I2[x] = Q2(x);
		I3[x] = Q3(x);
	}
}


