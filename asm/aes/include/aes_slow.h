#ifndef aes_slow_H_
#define aes_slow_H_

#include "aes.h"

void aes_encrypt_slow(struct aes_context *ctx, const uint8_t *in, uint8_t *out);
void aes_decrypt_slow(struct aes_context *ctx, const uint8_t *in, uint8_t *out);

#endif /* aes_slow_H_ */
