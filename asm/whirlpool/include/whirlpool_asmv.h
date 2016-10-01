#ifndef whirlpool_asmv_H_
#define whirlpool_asmv_H_

#include <stdint.h>

#define LE32(x)	(x)
#define LE64(x)	(x)
#define R64(x)	((x >> 32) | (x << 32))
#define BLOCK_NBYTES 64
#define WHIRLPOOL_NB 8

struct context_asmv {
	uint32_t length[2];
	uint8_t  buffer[64];
	uint64_t state[8];
};

void whirlpool_init_asmv(struct context_asmv *ctx);
void whirlpool_update_asmv(struct context_asmv *ctx, const void *msg, uint32_t msglen);
void whirlpool_final_asmv(struct context_asmv *ctx, unsigned char *result);

#endif /* whirlpool_asmv_H_ */
