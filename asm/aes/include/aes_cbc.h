#ifndef AES_CBC_H_
#define AES_CBC_H_

#include "aes.h"

#define BLOCK_NBYTES	16

#define CBC_ENCRYPT	1
#define CBC_DECRYPT	0

struct aes_cbc {
	/*Вектор инициализации IV*/
	uint8_t iv[16];
	/*Частичный буффер входного потока*/
	uint8_t buffer[16];
	/*Длина частичного буффера потока*/
	unsigned int len;
	/*Режим шифрования/дешифрования */
	int mode;
	/* Процедура кодирования блочного шифра*/
	void (*encode)(struct aes_context *ctx, const uint8_t *in, uint8_t *out);
	/*Структура для блочного шифра*/
	void *ctx;
};


/*Процедура инициализирует срутктуру aes_cbc */
void aes_cbc_init(struct aes_cbc *cbc,
		  void (*encode)(struct aes_context *ctx, const uint8_t *in, uint8_t *out),
		  void *ctx, int encr, unsigned char iv[16]);

/*Процедура производит шифрование и расшифрование блоков текста в режиме cbc */
void aes_cbc_update(struct aes_cbc *cbc, uint8_t *out, unsigned *out_len,
		    const uint8_t *in, unsigned in_len);

/*Последний раунд для  шифрования и расшифрования блоков текста в режиме cbc */
void aes_cbc_final(struct aes_cbc *cbc, uint8_t *out, unsigned *out_len);

/*Процедура очищяет структуру aes_cbc */
void aes_cbc_clean(struct aes_cbc *cbc);

#endif
