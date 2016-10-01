#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include "macros.h"

#include "../include/aes_slow.h"
#include "../include/galois.h"



uint8_t inv_sbox[256];
/*-------------------------------------------------------------------------- */

/*
Преобразование в процедурах шифрования и расшифрования,
заключающееся в сложении ключа раунда с матрицей состояния
с помощью операции XOR
*/
void add_round_key_slow(struct aes_context *ctx, int round) {
	uint8_t *wp;
	uint8_t *temp;

	wp = (uint8_t *)(ctx->w + AES_NB * round);
	temp = (uint8_t *)(ctx->state);

	for (int i = 0; i < AES_NB; i++) {
		for (int j = 0; j < AES_NB; j++)
			temp[4 * i + j] ^= wp[4 * i + j];
	}
}




/*-------------------------------------------------------------------------- */
/*Преобразование в процедуре шифрования, которое изkey_exменяет матрицу
состояния с помощью таблицы нелинейных замен(s-блока)
*/
void sub_bytes_slow(uint32_t *state) {
	uint8_t *temp =  (uint8_t *)(state);

	for (int i = 0; i < BLOCK_NBYTES; i++)
		temp[i] = transform_bits(temp[i]);
}




/*-------------------------------------------------------------------------- */
/*Генерация таблицы InvSbox*/
void create_inv_sbox()
{
	int i, j;

	for(i = 0; i < 256; i++) {
		j = transform_bits(i);
		inv_sbox[j] = i;
	 }
}



/*-------------------------------------------------------------------------- */
/*
Преобразование в процедуре дешифрования, которое изменяет матрицу
состояния с помощью таблицы нелинейных замен(обратного s-блока)
*/
void inv_sub_bytes_slow(uint32_t *state) {


	uint8_t *temp =  (uint8_t *)(state);

	for (int i = 0; i < BLOCK_NBYTES; i++) {
		temp[i] = inv_sbox[temp[i]];
	}
}

/*-------------------------------------------------------------------------- */
/*
Преобразование в процедуре шифрования, изменяющее матрицу состояния
путём циклического сдвига её трёх последних строк на различные смещения
*/
void shift_rows_slow(uint32_t* state) {

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
void inv_shift_rows_slow(uint32_t* state) {

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
Преобразование в процедуре шифрования, которое перемешивает
данные в каждом столбце матрицы состояния (независимо от других столбцов),
чтобы получить новое значение столбцов
*/
static void mix_columns_slow(uint32_t *state)
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

		n0 = gmul(0x2, *s0) ^ gmul(0x3, *s1) ^ *s2 ^ *s3;
		n1 = *s0 ^ gmul(0x2, *s1) ^ gmul(0x3, *s2) ^ *s3;
		n2 = *s0 ^ *s1 ^ gmul(0x2, *s2) ^ gmul(0x3, *s3);
		n3 = gmul(0x3, *s0) ^ *s1 ^ *s2 ^ gmul(0x2, *s3);

		/* Запоминаем результат, переход к следующему столбцу*/
		*s0++ = n0;
		*s1++ = n1;
		*s2++ = n2;
		*s3++ = n3;
	}
}
/*-------------------------------------------------------------------------- */
/*
Преобразование в процедуре дешифрования, которое перемешивает
данные в каждом столбце матрицы состояния (независимо от других столбцов),
чтобы получить новое значение столбцов
*/
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

		/* Запоминаем результат, переход к следующему столбцу*/
		*s0++ = n0;
		*s1++ = n1;
		*s2++ = n2;
		*s3++ = n3;
	}
}

/*-------------------------------------------------------------------------- */
/*
Процедура шифрования
*/
void aes_encrypt_slow(struct aes_context *ctx_slow, const uint8_t *input, uint8_t *output) {

	uint8_t *sp;

	sp = (uint8_t *) ctx_slow->state;

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++)
			sp[i * 4 + j] = input[j * 4 + i];
	}

 	add_round_key_slow(ctx_slow, 0);

	for (int i = 1; i < ctx_slow->nr; i++) {
		sub_bytes_slow(ctx_slow->state);
		shift_rows_slow(ctx_slow->state);
		mix_columns_slow(ctx_slow->state);
		add_round_key_slow(ctx_slow, i);
	}
	sub_bytes_slow(ctx_slow->state);
	shift_rows_slow(ctx_slow->state);
	add_round_key_slow(ctx_slow, ctx_slow->nr);

	for (int i = 0; i < AES_NB; i++) {
			for (int j = 0; j < AES_NB; j++)
				output[i * AES_NB + j] = sp[j * AES_NB + i];
		}
}

/*-------------------------------------------------------------------------- */
/*
Процедура расшифрования
*/
void aes_decrypt_slow(struct aes_context *ctx_slow, const uint8_t *input, uint8_t *output) {
	uint8_t *sp;

	sp = (uint8_t *) ctx_slow->state;

	for (int i = 0; i < AES_NB; i++) {
		for (int j = 0; j < AES_NB; j++)
			sp[i * AES_NB + j] = input[j * AES_NB + i];
	}
	create_inv_sbox();
	add_round_key_slow(ctx_slow,  ctx_slow->nr);
	for (int i = ctx_slow->nr - 1; i > 0; i-- ) {
		inv_shift_rows_slow(ctx_slow->state);
		inv_sub_bytes_slow(ctx_slow->state);
		add_round_key_slow(ctx_slow, i);
		inv_mix_columns_slow(ctx_slow->state);
	}
	inv_shift_rows_slow(ctx_slow->state);
	inv_sub_bytes_slow(ctx_slow->state);
	add_round_key_slow(ctx_slow, 0);

	for (int i = 0; i < AES_NB; i++) {
			for (int j = 0; j < AES_NB; j++)
				output[i * AES_NB + j] = sp[j * AES_NB + i];
		}
}


//*-------------------------------------------------------------------------- */


