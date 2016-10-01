#ifndef aes_asmv_H_
#define aes_asmv_H_

#include "aes.h"

void aes_encrypt_asmv(struct aes_context *ctx, const uint8_t *in, uint8_t *out);
void aes_decrypt_asmv(struct aes_context *ctx, const uint8_t *in, uint8_t *out);

#endif /* aes_H_ */
