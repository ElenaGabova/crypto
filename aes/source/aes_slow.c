
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>


#include "aes_slow.h"

#include "macros.h"
#include "galois.h"


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define CreateWord(b0, b1, b2, b3)	\
	((b0 & 0xff) | ((b1 << 8) & 0xff00) | \
	 ((b2 << 16) & 0xff0000) | ((b3 << 24) & 0xff000000))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define CreateWord(b0, b1, b2, b3) \
	((b3 & 0xff) | ((b2 << 8) & 0xff00) | \
	 ((b1 << 16) & 0xff0000) | ((b0 << 24) & 0xff000000))
#else
#error unsupported byte order
#endif

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
	
static const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Tables used by MixColumns procedure. */
static uint32_t M0[256];
static uint32_t M1[256];
static uint32_t M2[256];
static uint32_t M3[256];

/* Tables used by InvMixColumns procedure. */
static uint32_t I0[256];
static uint32_t I1[256];
static uint32_t I2[256];
static uint32_t I3[256];


const uint32_t rcon[] = { 
	  	 0x01, 0x02, 0x04, 0x08, 
		0x10, 0x20, 0x40, 0x80, 
		0x1B, 0x36
	};


/*-------------------------------------------------------------------------- */
/*
Функция, используемая в процедуре расширения ключа.
Выполняет циклическую перестановку внутри 4-байтного словa
*/
uint32_t rot_word(uint32_t word) 
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	word = (word >> 8) | (word << 24);

#elif __BYTE_ORDER == __BIG_ENDIAN
	word = (word << 8) | (word >> 24);

#else
	#error unsupported byte order
#endif

	return word;
}

/*-------------------------------------------------------------------------- */
/*
Процедура используемая в процедуре расширения ключа.
На вход функции поступает 4-байтное слово. Выходное слово формируется 
путём замены каждого из этих четырёх байт с помощью s-блока.
*/
static uint32_t sub_word(uint32_t word) {
	
	uint32_t temp;

	temp = (sbox[word & 0xff] );
	for (int i = 1 ; i < 4; i++)
		temp |= (sbox[(word >> 8*i) & 0xff] << 8*i);
	return temp;	
}

/*-------------------------------------------------------------------------- */
/*
Процедура расширения ключа
*/
void key_expansion(struct aes_context *ctx) {
	
	uint32_t temp;
	int keysize = ctx->nb;
  	int expanded_keysize =  4 *(ctx->nr + 1);
	int rcon_itteration = 0;
	int nk = ctx->nk;

	for( int i = ctx->nk; i < expanded_keysize; i++) {
			 temp = ctx->w[i - 1];
				if (i % nk == 0) 
				temp = sub_word(rot_word(temp))  ^ rcon[rcon_itteration++];

		else if (ctx->nk > 6 && (i % nk) == AES_NB)  temp = sub_word(temp);
		ctx->w[i] = ctx->w[i- ctx->nk] ^ temp;
	}
}

/*-------------------------------------------------------------------------- */
/*
Преобразование в процедурах шифрования и расшифрования,
заключающееся в сложении ключа раунда с матрицей состояния
с помощью операции XOR
*/
void add_round_key(struct aes_context *ctx, int round) {
	uint8_t *wp;
	uint8_t *temp;

	wp = (uint8_t *)(ctx->w + AES_NB * round);
	temp = (uint8_t *)(ctx->state);

	for (int i = 0; i < AES_NB; i++) { 
		for (int j = 0; j < AES_NB; j++)
			temp[4 * i + j] ^= wp[4 * j + i];
	}
}



/*-------------------------------------------------------------------------- */
/*Преобразование в процедуре шифрования, которое изменяет матрицу
состояния с помощью таблицы нелинейных замен(s-блока)
*/
void sub_bytes(uint32_t *state) {
	uint8_t *temp =  (uint8_t *)(state);

	for (int i = 0; i < BLOCK_NBYTES; i++) 
		temp[i] = sbox[temp[i]];
}


/*-------------------------------------------------------------------------- */
/*
Преобразование в процедуре дешифрования, которое изменяет матрицу
состояния с помощью таблицы нелинейных замен(обратного s-блока)
*/
void inv_sub_bytes(uint32_t *state) {
	uint8_t *temp =  (uint8_t *)(state);

	for (int i = 0; i < BLOCK_NBYTES; i++) 
		temp[i] = inv_sbox[temp[i]];
}

/*-------------------------------------------------------------------------- */
/*
Преобразование в процедуре шифрования, изменяющее матрицу состояния
путём циклического сдвига её трёх последних строк на различные смещения
*/
void shift_rows(uint32_t* state) {
	
	int i;
	uint32_t *s = state;

	#if __BYTE_ORDER == __LITTLE_ENDIAN
		s[1] = s[1] >> 8 | s[1] << 24;
		s[2] = s[2] >> 16 | s[2] << 16;
		s[3] = s[3] << 8 | s[3] >> 24;

	#elif __BYTE_ORDER == __BIG_ENDIAN
		s[1] = s[1] << 8 | s[1] >> 24;
		s[2] = s[2] << 16 | s[2] >> 16;
		s[3] = s[3] >> 8 | s[3] << 24;

	#else
		#error unsupported byte order
	#endif

}

/*-------------------------------------------------------------------------- */
/*
Преобразование в процедуре расшифрования, которое является обратным к shift_rows()
*/
void inv_shift_rows(uint32_t* state) {
	
	int i;
	uint32_t *s = state;

	#if __BYTE_ORDER == __LITTLE_ENDIAN
		s[1] = s[1] << 8 | s[1] >> 24;
		s[2] = s[2] << 16 | s[2] >> 16;
		s[3] = s[3] >> 8 | s[3] << 24;

	#elif __BYTE_ORDER == __BIG_ENDIAN
		s[1] = s[1] >> 8 | s[1] << 24;
		s[2] = s[2] >> 16 | s[2] << 16;
		s[3] = s[3] << 8 | s[3] >> 24;

	#else
		#error unsupported byte order
	#endif
}

/*-------------------------------------------------------------------------- */
/*
Уможение многочлена a на x в конечном поле GF (2^8)
*/
uint8_t xtime(uint8_t x) {
	return (x & 0x80) ? ( (x << 1) ^ 0x1b) : (x << 1);
} 

/*-------------------------------------------------------------------------- */
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

/*-------------------------------------------------------------------------- */
/*
Преобразование в процедуре шифрования, которое перемешивает
данные в каждом столбце матрицы состояния (независимо от других столбцов),
чтобы получить новое значение столбцов
*/
static void
mix_columns_slow(uint32_t *state)
{
	uint8_t *s0, *s1, *s2, *s3;
	uint8_t n0, n1, n2, n3;
	int i, nb;

	nb = 4;
	s0 = (uint8_t *) state + (nb*0);
	s1 = (uint8_t *) state + (nb*1);
	s2 = (uint8_t *) state + (nb*2);
	s3 = (uint8_t *) state + (nb*3);

	for (i = 0; i < nb; i++) {
		/* Calculate matrix multiplication. */
		n0 = gmul(0x2, *s0) ^ gmul(0x3, *s1) ^ *s2 ^ *s3;
		n1 = *s0 ^ gmul(0x2, *s1) ^ gmul(0x3, *s2) ^ *s3;
		n2 = *s0 ^ *s1 ^ gmul(0x2, *s2) ^ gmul(0x3, *s3);
		n3 = gmul(0x3, *s0) ^ *s1 ^ *s2 ^ gmul(0x2, *s3);
		/* Store results into state and skip to next column. */
		*s0++ = n0;
		*s1++ = n1;
		*s2++ = n2;
		*s3++ = n3;
	}
}

/*-------------------------------------------------------------------------- */
static void mix_columns(uint32_t *state)
{
	uint8_t *s0, *s1, *s2, *s3;
	uint32_t res;

	s0 = (uint8_t *) state;
	s1 = (uint8_t *) state + 4;
	s2 = (uint8_t *) state + 8;
	s3 = (uint8_t *) state + 12;

	res = M0[*s0] ^ M1[*s1] ^ M2[*s2] ^ M3[*s3];
	*s0++ = res & 0xff;
	*s1++ = (res & 0xff00) >> 8;
	*s2++ = (res & 0xff0000) >> 16;
	*s3++ = (res & 0xff000000) >> 24;

	res = M0[*s0] ^ M1[*s1] ^ M2[*s2] ^ M3[*s3];
	*s0++ = res & 0xff;
	*s1++ = (res & 0xff00) >> 8;
	*s2++ = (res & 0xff0000) >> 16;
	*s3++ = (res & 0xff000000) >> 24;

	res = M0[*s0] ^ M1[*s1] ^ M2[*s2] ^ M3[*s3];
	*s0++ = res & 0xff;
	*s1++ = (res & 0xff00) >> 8;
	*s2++ = (res & 0xff0000) >> 16;
	*s3++ = (res & 0xff000000) >> 24;

	res = M0[*s0] ^ M1[*s1] ^ M2[*s2] ^ M3[*s3];
	*s0 = res & 0xff;
	*s1 = (res & 0xff00) >> 8;
	*s2 = (res & 0xff0000) >> 16;
	*s3 = (res & 0xff000000) >> 24;
}
/*-------------------------------------------------------------------------- */
static void inv_mix_columns_slow(uint32_t *state)
{
	uint8_t *s0, *s1, *s2, *s3;
	uint8_t n0, n1, n2, n3;
	int i, nb;

	nb = 4;
	s0 = (uint8_t *) state + (nb*0);
	s1 = (uint8_t *) state + (nb*1);
	s2 = (uint8_t *) state + (nb*2);
	s3 = (uint8_t *) state + (nb*3);

	for (i = 0; i < nb; i++) {
	
		n0 = gmul(0xe, *s0) ^ gmul(0xb, *s1) ^ gmul(0xd, *s2) ^ gmul(0x9, *s3);
		n1 = gmul(0x9, *s0) ^ gmul(0xe, *s1) ^ gmul(0xb, *s2) ^ gmul(0xd, *s3);
		n2 = gmul(0xd, *s0) ^ gmul(0x9, *s1) ^ gmul(0xe, *s2) ^ gmul(0xb, *s3);
		n3 = gmul(0xb, *s0) ^ gmul(0xd, *s1) ^ gmul(0x9, *s2) ^ gmul(0xe, *s3);
	
		*s0++ = n0;
		*s1++ = n1;
		*s2++ = n2;
		*s3++ = n3;
	}
}
/*-------------------------------------------------------------------------- */
static void inv_mix_columns(uint32_t *state)
{
	uint8_t *s0, *s1, *s2, *s3;
	uint32_t res;

	s0 = (uint8_t *) state;
	s1 = (uint8_t *) state + 4;
	s2 = (uint8_t *) state + 8;
	s3 = (uint8_t *) state + 12;

	/* state matrix column S(j,0), j=0..3 */
	res = I0[*s0] ^ I1[*s1] ^ I2[*s2] ^ I3[*s3];
	*s0++ = res & 0xff;
	*s1++ = (res & 0xff00) >> 8;
	*s2++ = (res & 0xff0000) >> 16;
	*s3++ = (res & 0xff000000) >> 24;

	res = I0[*s0] ^ I1[*s1] ^ I2[*s2] ^ I3[*s3];
	*s0++ = res & 0xff;
	*s1++ = (res & 0xff00) >> 8;
	*s2++ = (res & 0xff0000) >> 16;
	*s3++ = (res & 0xff000000) >> 24;

	res = I0[*s0] ^ I1[*s1] ^ I2[*s2] ^ I3[*s3];
	*s0++ = res & 0xff;
	*s1++ = (res & 0xff00) >> 8;
	*s2++ = (res & 0xff0000) >> 16;
	*s3++ = (res & 0xff000000) >> 24;

	res = I0[*s0] ^ I1[*s1] ^ I2[*s2] ^ I3[*s3];
	*s0 = res & 0xff;
	*s1 = (res & 0xff00) >> 8;
	*s2 = (res & 0xff0000) >> 16;
	*s3 = (res & 0xff000000) >> 24;
}

/*-------------------------------------------------------------------------- */
/*
Процедура шифрования
*/
void aes_encrypt(struct aes_context *ctx, uint8_t *input, uint8_t *output) { 
	
	uint8_t *sp;
	
	sp = (uint8_t *) ctx->state;

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) 
			sp[i * 4 + j] = input[j * 4 + i];
	}

 	add_round_key(ctx, 0);

	for (int i = 1; i < ctx->nr; i++) {
		sub_bytes(ctx->state);
		shift_rows(ctx->state);
		mix_columns_slow(ctx->state);
		add_round_key(ctx, i);
	}	
	sub_bytes(ctx->state);
	shift_rows(ctx->state);
	add_round_key(ctx, ctx->nr);
	
	for (int i = 0; i < AES_NB; i++) {
			for (int j = 0; j < AES_NB; j++) 
				output[i * AES_NB + j] = sp[j * AES_NB + i];
		}
}

/*-------------------------------------------------------------------------- */
/*
Процедура расшифрования
*/
void aes_decrypt(struct aes_context *ctx, uint8_t *input, uint8_t *output) { 
	uint8_t *sp;

	sp = (uint8_t *) ctx->state;

	for (int i = 0; i < AES_NB; i++) {
		for (int j = 0; j < AES_NB; j++) 
			sp[i * AES_NB + j] = input[j * AES_NB + i];
	}

	add_round_key(ctx,  ctx->nr);
	for (int i = ctx->nr - 1; i > 0; i-- ) {
		inv_shift_rows(ctx->state);
		inv_sub_bytes(ctx->state);
		add_round_key(ctx, i);
		inv_mix_columns_slow(ctx->state);
	}	
	inv_shift_rows(ctx->state);
	inv_sub_bytes(ctx->state);	
	add_round_key(ctx, 0);
	
	for (int i = 0; i < AES_NB; i++) {
			for (int j = 0; j < AES_NB; j++) 
				output[i * AES_NB + j] = sp[j * AES_NB + i];
		}
}

/*-------------------------------------------------------------------------- */
/*
Процедура создания ключа
*/
void aes_set_key(struct aes_context *ctx, uint8_t *key, aes_key_len keyLength) {
	ctx->keysize = keyLength;
	switch (ctx->keysize) {
		case BITS_128:
			ctx->nk = 4;  
			ctx->nr = 10;
			break;
		case BITS_192:
			ctx->nk = 6; 
			ctx->nr = 12;
			break;
		case BITS_256:
			ctx->nk = 8;  
			ctx->nr = 14;
			break;
	}	
	ctx->nb = AES_NB;
	memcpy(ctx->expanded_key, key, ctx->nk * AES_NB);
	memcpy(ctx->w,ctx->expanded_key, ctx->nk * AES_NB);
	key_expansion(ctx);

}

/*-------------------------------------------------------------------------- */
/*
Создание новой структуры шифрования aes 
*/
struct aes_context *aes_context_new()
{
        struct aes_context *ctx;

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                return NULL;
        memset(ctx, 0, sizeof(*ctx));
        ctx->nr = -1;
        ctx->nb = -1;
        ctx->nk = -1;

        return ctx;
}

/*-------------------------------------------------------------------------- */
/*
Инициализация структуры шифрования aes
*/
void aes_context_init(struct aes_context *ctx) {
	ctx = malloc(sizeof (*ctx));
}

/*-------------------------------------------------------------------------- */
/*Процедура освобождает все ресурсы, связанные с контекстом
*/
void aes_context_free(struct aes_context *ctx) {
	ctx = NULL;
}

/*-------------------------------------------------------------------------- */
/*
Процедура очищает структуру aes
*/
void aes_context_clean(struct aes_context *ctx) {
	memset(ctx, 0, sizeof (*ctx));
}

//*-------------------------------------------------------------------------- */


