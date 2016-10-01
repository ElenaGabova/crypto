#ifndef aes_H_
#define aes_H_

#define BLOCK_NBYTES	16
#define AES_NB  4

typedef enum { 
	 BITS_128, //При размере ключа 128 бит длинна ключа 16 байт
	 BITS_192, //При размере ключа 192 бит длинна ключа 24 байта
	 BITS_256 //При размере ключа 256 бит длинна ключа 32 байта
} aes_key_len;

struct aes_context {
	/*Секретный ключ*/
	uint32_t 	expanded_key[8];
	/*Размер ключа шифорвания*/
	aes_key_len 	keysize;
	/*Блок данных, размером 128 бит, 16 байт*/
	uint32_t 	state[AES_NB];
	/*Количество 32-битных слов, составляющих ключ шифрования. nk = 4, 6 или 8*/
	uint32_t 	nk;
	/*Количество раундов. Для данного стандарта nr = 10, 12 или 14*/
	uint32_t	nr; 
	/*Количество столбцов в матрице состояния. Для данного стандарта nb = 4*/
	uint32_t 	nb; 
	/*Открытый ключ*/
	uint32_t	w[AES_NB*(14+1)];
	
};


/* Процедура очищает структуру aes */
void aes_context_clean(struct aes_context *ctx);

/* Инициализация структуры aes */
void aes_context_init(struct aes_context *ctx);

/* Процедура освобождает все ресурсы, связанные с контекстом */
void aes_context_free(struct aes_context *ctx);

/*Процедура создания ключа */
void aes_set_key(struct aes_context *ctx, uint8_t *key, aes_key_len keyLength);

/*инициализация ключа*/

struct aes_context *aes_context_new();

/* Процедура шифрует 128-битный блок 'input', и подставляет его в 128-битный блок 'output' . */
void aes_encrypt(struct aes_context *ctx, uint8_t *input, uint8_t *output);
/* Процедура дешифрует 128-битный блок 'input', и подставляет его в 128-битный блок 'output' .*/
void aes_decrypt(struct aes_context *ctx, uint8_t *input, uint8_t *output);

#endif /* aes_H_ */
