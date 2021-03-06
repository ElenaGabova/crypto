#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <time.h>    

#include "whirlpool_slow.h"
#include "galois.h"

  
#define LE32(x)	(x)
#define LE64(x)	(x)
#define R64(x)	((x >> 32) | (x << 32))
#define BLOCK_NBYTES	64
#define WHIRLPOOL_NB  8


const uint64_t cr[10] = {
	LE64(0x4f01b887e8c62318LLU), LE64(0x52916f79f5d2a636LLU),
	LE64(0x357b0ca38e9bbc60LLU), LE64(0x57fe4b2ec2d7e01dLLU),
	LE64(0xda4af09fe5377715LLU), LE64(0x856ba0b10a29c958LLU),
	LE64(0x67053ecbf4105dbdLLU), LE64(0xd8957da78b4127e4LLU),
	LE64(0x9e4717dd667ceefbLLU), LE64(0x33835aad07bf2dcaLLU)
};


/*
Преобразование в процедуре шифрования, изменяющее матрицу состояния
путём циклическоMIX64го сдвига её трёх последних столбцов на различные смещения
*/

void shift_columns(uint64_t state[8]) {

	uint8_t *temp = (uint8_t *) state;
	uint8_t b[8];
	int i, j, shift;

	for(i = 1; i < WHIRLPOOL_NB; i++){

		for(j = 0; j < WHIRLPOOL_NB; j++) {
			shift = i + 8 * ((8 + j - i) % 8);
			b[j] = temp[shift];
			
		}
		for(j = 0; j < WHIRLPOOL_NB; j++)	
			temp[j * 8 + i] = b[j];
	}
}




/*-------------------------------------------------------------------------- */
/* Cложение ключа раунда с матрицей состояния
с помощью операции XOR*/
void add_round_key(uint64_t state[8], uint64_t rk[8]) {
	
	int i;

	for(i = 0; i < WHIRLPOOL_NB; i++) 
		state[i] ^= rk[i];
}

/*-------------------------------------------------------------------------- */
/* Процедура блочного шифрования W */
void whirlpool_hash(uint64_t s[8], const unsigned char buffer[64]) {

	int i;
	uint64_t state[8];
	uint64_t key[8];

	memcpy(key, s, BLOCK_NBYTES);
	memcpy(state, buffer, BLOCK_NBYTES);
	add_round_key(state, key);

	for (i = 0; i < 10; i++) {

		sub_bytes_slow(key);
		sub_bytes_slow(state);

		shift_columns(key);
		shift_columns(state);
		
		mix_rows_slow((uint32_t *) key);
		mix_rows_slow((uint32_t *) state);
		
		key[0] ^= cr[i];
		add_round_key(state, key);

	}

	for (i = 0; i < WHIRLPOOL_NB; i++)
		s[i] ^= state[i] ^ ((uint64_t *)buffer)[i];

}


/*-------------------------------------------------------------------------- */
/* Инициализация структуры context */
void whirlpool_init(struct context *ctx) {
	
	int i;
	ctx->length[0] = 0;
	ctx->length[1] = 0;

	for (i = 0; i < WHIRLPOOL_NB; i++) {
		ctx->buffer[i] = 0;
		ctx->state[i] = 0;
	}

}


/*-------------------------------------------------------------------------- */
void whirlpool_update(struct context *ctx, const void *msg, uint32_t msglen)
{
	unsigned int n, len;

	n = ctx->length[0] & 0x3F;
	ctx->length[0] += msglen;
	if (n + msglen < 64) {
		/* just copy the message to the buffer */
		memcpy(ctx->buffer + n, msg, msglen);
	} else {
		/* copy and hash a part of message */
		len = 64 - n;
		memcpy(ctx->buffer + n, msg, len);
		whirlpool_hash(ctx->state, ctx->buffer);
		msglen -= len;
		msg += len;
		/* copy and hash 64-byte blocks */
		while (msglen >= 64) {
			memcpy(ctx->buffer, msg, 64);
			whirlpool_hash(ctx->state, ctx->buffer);
			msglen -= len;
			msg += len;
		}
		/* copy remainder of the message */
		memcpy(ctx->buffer, msg, msglen);
	}
}
/*-------------------------------------------------------------------------- */
static void
uint32_to_bytes(unsigned char *out, const uint32_t *in)
{
	int i, j;

	for (i = j = 0; j < 3; j++) {
		out[i++] = (in[j] >> 24) & 0xff;
		out[i++] = (in[j] >> 16) & 0xff;
		out[i++] = (in[j] >> 8) & 0xff;
		out[i++] = in[j] & 0xff;
	}
}
/*-------------------------------------------------------------------------- */
void whirlpool_final(struct context *ctx, unsigned char digest[64])
{
	static const unsigned char pad[64] = { 0x80, 0x0 };
	unsigned int n, npad;
	uint32_t nbits[3];
	uint8_t nb[32];

	//n = ((ctx->length[0] < 64) ? ctx->length[0]: ctx->length[0] - 64);
	//npad = ((n < 32) ? 32: 96) - n;
	n = ctx->length[0] & 0x3f;
	npad = ((n < 32) ? 32: 96) - n;

	nbits[0] = nbits[1] = 0;
	nbits[1] += ctx->length[0] >> 29;
	nbits[2] = ctx->length[0] << 3;

	memset(nb, 0, sizeof(nb));
	uint32_to_bytes(nb+20, nbits);

	whirlpool_update(ctx, pad, npad);
	whirlpool_update(ctx, nb, 32);

	memcpy(digest, ctx->state, 64);
}


/*-------------------------------------------------------------------------- */

