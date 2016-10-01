#ifndef aes_slou_H_
#define aes_slou_H_

#include "aes.h"

void aes_encrypt_slou(struct aes_context *ctx, const uint8_t *in, uint8_t *out);
void aes_decrypt_slou(struct aes_context *ctx, const uint8_t *in, uint8_t *out);

#endif /* aes_slou_H_ */
