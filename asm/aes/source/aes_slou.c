#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include "macros.h"

#include "../include/aes_slou.h"
#include "../include/galoisu.h"

static void
vec4_uint32_xoru(uint32_t dest[4], uint32_t src[4])
{
	dest[0] ^= src[0];
	dest[1] ^= src[1];
	dest[2] ^= src[2];
	dest[3] ^= src[3];
}

static void
add_round_key_slou(struct aes_context *ctx, int round)
{
	vec4_uint32_xoru(ctx->state, ctx->w + AES_NB * round);
}

static void
sub_bytes_slou(uint32_t *state)
{
	uint8_t *temp = (uint8_t *)(state);

	for (int i = 0; i < BLOCK_NBYTES; i++)
		temp[i] = transform_bitsu(temp[i]);
}

static void
inv_sub_bytes_slou(uint32_t *state)
{
	uint8_t *temp = (uint8_t *)(state);

	for (int i = 0; i < BLOCK_NBYTES; i++)
		temp[i] = inv_transform_bitsu(temp[i]);
}

static void
shift_rows_slou(uint32_t* state)
{
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

static void
inv_shift_rows_slou(uint32_t* state)
{
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

static void
mix_columns_slou(uint32_t *state)
{
	uint8_t buf[28];

	memcpy(buf, state, 16);
	memcpy(buf + 16, state, 12);

	/* state = [s4, …, s15, s0, …, s3] */
	memcpy(state, buf + 4, 16);
	/* state ^= [s8, …, s15, s0, …, s7] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 8));
	/* state ^= [s12, …, s15, s0, …, s11] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 12));
	/* Умножение на 2 в поле Rijndael */
	g2times(buf, 20);
	/* state ^= [2 * s0, …, 2 * s15] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 0));
	/* state ^= [2 * s4, …, 2 * s15, 2 * s0, …, 2 * s3] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 4));
}

static void
inv_mix_columns_slou(uint32_t *state)
{
	uint8_t buf[28];

	memcpy(buf, state, 16);
	memcpy(buf + 16, state, 12);

	/* state = [s4, …, s15, s0, …, s3] */
	memcpy(state, buf + 4, 16);
	/* state ^= [s8, …, s15, s0, …, s7] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 8));
	/* state ^= [s12, …, s15, s0, …, s11] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 12));
	/* Умножение на 2 в поле Rijndael */
	g2times(buf, 28);
	/* state ^= [2 * s0, …, 2 * s15] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 0));
	/* state ^= [2 * s4, …, 2 * s15, 2 * s0, …, 2 * s3] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 4));
	/* Умножение на 2 в поле Rijndael */
	g2times(buf, 28);
	/* state ^= [4 * s0, …, 4 * s15] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 0));
	/* state ^= [4 * s8, …, 4 * s15, 4 * s0, …, 4 * s7] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 8));
	/* Умножение на 2 в поле Rijndael */
	g2times(buf, 28);
	/* state ^= [8 * s0, …, 8 * s15] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 0));
	/* state ^= [8 * s4, …, 8 * s15, 8 * s0, …, 8 * s3] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 4));
	/* state ^= [8 * s8, …, 8 * s15, 8 * s0, …, 8 * s7] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 8));
	/* state ^= [8 * s12, …, 8 * s15, 8 * s0, …, 8 * s11] */
	vec4_uint32_xoru(state, (uint32_t *) (buf + 12));
}

void
aes_encrypt_slou(struct aes_context *ctx_slou, const uint8_t *input, uint8_t *output)
{
	uint8_t *sp;

	sp = (uint8_t *) ctx_slou->state;

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++)
			sp[i * 4 + j] = input[j * 4 + i];
	}

 	add_round_key_slou(ctx_slou, 0);

	for (int i = 1; i < ctx_slou->nr; i++) {
		sub_bytes_slou(ctx_slou->state);
		shift_rows_slou(ctx_slou->state);
		mix_columns_slou(ctx_slou->state);
		add_round_key_slou(ctx_slou, i);
	}
	sub_bytes_slou(ctx_slou->state);
	shift_rows_slou(ctx_slou->state);
	add_round_key_slou(ctx_slou, ctx_slou->nr);

	for (int i = 0; i < AES_NB; i++) {
			for (int j = 0; j < AES_NB; j++)
				output[i * AES_NB + j] = sp[j * AES_NB + i];
		}
}

void
aes_decrypt_slou(struct aes_context *ctx_slou, const uint8_t *input, uint8_t *output)
{
	uint8_t *sp;

	sp = (uint8_t *) ctx_slou->state;

	for (int i = 0; i < AES_NB; i++)
		for (int j = 0; j < AES_NB; j++)
			sp[i * AES_NB + j] = input[j * AES_NB + i];

	add_round_key_slou(ctx_slou,  ctx_slou->nr);
	for (int i = ctx_slou->nr - 1; i > 0; i-- ) {
		inv_shift_rows_slou(ctx_slou->state);
		inv_sub_bytes_slou(ctx_slou->state);
		add_round_key_slou(ctx_slou, i);
		inv_mix_columns_slou(ctx_slou->state);
	}
	inv_shift_rows_slou(ctx_slou->state);
	inv_sub_bytes_slou(ctx_slou->state);
	add_round_key_slou(ctx_slou, 0);

	for (int i = 0; i < AES_NB; i++)
		for (int j = 0; j < AES_NB; j++)
			output[i * AES_NB + j] = sp[j * AES_NB + i];
}


//*-------------------------------------------------------------------------- */


