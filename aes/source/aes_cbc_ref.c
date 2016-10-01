#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "aes_cbc_ref.h"


#define CBC(out, iv) 			   \
{					   \
	uint32_t *p = (uint32_t *) (out);  \
	uint32_t *p2 = (uint32_t *) (iv);  \
	for (int i = 0; i < 4; i++)	   \
		*p++ ^= *p2++; 		   \
}

/*-------------------------------------------------------------------------- */
/*Процедура очищяет структуру aes_cbc*/
void aes_cbc_clean(struct aes_cbc *cbc) {
	memset(cbc->iv, 0, sizeof(cbc->iv));
	memset(cbc->buffer, 0, sizeof(cbc->buffer));
}


/*-------------------------------------------------------------------------- */
/*Процедура инициализирует срутктуру aes_cbc*/
void aes_cbc_init(struct aes_cbc *cbc,
		  void (*encode)(void *ctx, const void *in, void *out), 
		  void *ctx, int encr, unsigned char iv[16])
{
	memset(cbc->buffer , 0, sizeof(cbc->buffer));
	memcpy(cbc->iv , iv, sizeof(cbc->iv));
	cbc->len = 0;
	cbc->encode = encode;
	cbc->ctx = ctx;
	cbc-> mode = encr ? CBC_ENCRYPT : CBC_DECRYPT;
}


/*-------------------------------------------------------------------------- */
/*Процедура производит шифрование и расшифрование блоков текста в режиме cbc*/
void aes_cbc_update(struct aes_cbc *cbc, void *out, unsigned *out_len,
		    const void *in, unsigned in_len)
{
	int n, space;

	n = cbc->len;
	space = BLOCK_NBYTES - n;
	*out_len = 0;

	if (n > 0 && space > 0) {
		memcpy(cbc->buffer + n, in, space);
		cbc->len += n;
		in += n;
		in_len -= n;
	}
	if (cbc->len >= BLOCK_NBYTES) {
		if (cbc->mode == CBC_ENCRYPT) {
			CBC(cbc->buffer, cbc->iv);
			(*cbc->encode)(cbc->ctx, cbc->buffer, out);
			memcpy(cbc->iv, out, BLOCK_NBYTES);
		}
		else {
			(*cbc->encode)(cbc->ctx, cbc->buffer, out);
			CBC(out, cbc->iv);
			memcpy(cbc->iv, cbc->buffer, BLOCK_NBYTES);
		}
		*out_len += BLOCK_NBYTES;
		out += BLOCK_NBYTES;
		cbc->len = 0;
	}
			
	while (in_len >= BLOCK_NBYTES) {
		
		memcpy(out, in, BLOCK_NBYTES);
		if (cbc->mode == CBC_ENCRYPT) {
			/*Сцепляем блоки для режима шифрования*/
			CBC(out, cbc->iv);

			/*Шифруем блок out*/
			(*cbc->encode)(cbc->ctx, out, out);

			/*Сохраняем текущий блок для построения следующего*/
			memcpy(cbc->iv, out, BLOCK_NBYTES);
		}
		else {
			/*Расшифровываем блок out*/
			(*cbc->encode)(cbc->ctx, out, out);

			/*Сцепляем блоки для режима дeшифрования*/
			CBC(out, cbc->iv);

			/*Сохраняем текущий блок для построения следующего*/
			memcpy(cbc->iv, in, BLOCK_NBYTES);
		}
		*out_len += BLOCK_NBYTES;
		out += BLOCK_NBYTES;
		in += BLOCK_NBYTES;		
		in_len -= BLOCK_NBYTES;

	}
	
	if (in_len > 0) {
		n = cbc->len;
		memcpy(cbc->buffer + n, in, in_len);
		cbc->len += in_len;
	}
}


/*-------------------------------------------------------------------------- */
/*Последний раунд для  шифрования и расшифрования блоков текста в режиме cbc*/
void aes_cbc_final(struct aes_cbc *cbc, void *out, unsigned *out_len)
{
	int n, space;

	n = cbc->len;
	space = BLOCK_NBYTES - n;
	*out_len = 0;

	if (n > 0) {
		memset(cbc->buffer + n, space, space);
		
	/*Кодируем последний блок*/
		if (cbc->mode == CBC_ENCRYPT) {
			CBC(cbc->buffer, cbc->iv);
			(*cbc->encode)(cbc->ctx, cbc->buffer, out);
			memcpy(cbc->iv, out, BLOCK_NBYTES);
		}
		else {
			 (*cbc->encode)(cbc->ctx, cbc->buffer, out);
			CBC(out, cbc->iv);
			memcpy(cbc->iv, cbc->buffer, BLOCK_NBYTES);
		}
		*out_len = n;
	}
}
	
		
