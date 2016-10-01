#ifndef whirlpool_slow_H_
#define whirlpool_slow_H_

#include <stdint.h>



#define LE32(x)	(x)
#define LE64(x)	(x)
#define R64(x)	((x >> 32) | (x << 32))
#define BLOCK_NBYTES 64
#define WHIRLPOOL_NB 8


struct context_slow {
	uint32_t length[2];
	uint8_t  buffer[64];
	uint64_t state[8];
};

/*----------------------------------------------------*/
/*Init structure*/
void whirlpool_init_slow(struct context_slow *ctx);


/*----------------------------------------------------*/
/*add element to whirlpool structure*/
void whirlpool_update_slow(struct context_slow *ctx, const void *msg, uint32_t msglen);


/*----------------------------------------------------*/
/*final round*/
void whirlpool_final_slow(struct context_slow *ctx, unsigned char *result);

#endif /* whirlpool_slow_H_ */
