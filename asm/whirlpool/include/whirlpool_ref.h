#ifndef whirlpool_H_
#define whirlpool_H_

#include <stdint.h>



#define LE32(x)	(x)
#define LE64(x)	(x)
#define R64(x)	((x >> 32) | (x << 32))
#define BLOCK_NBYTES	64
#define WHIRLPOOL_NB  8


struct context_ref{
	uint32_t length[2];
	uint8_t  buffer[64];
	uint64_t state[8];
};

/*----------------------------------------------------*/
/*Init structure*/
void whirlpool_init_ref(struct context_ref *ctx);


/*----------------------------------------------------*/
/*add element to whirlpool structure*/
void whirlpool_update_ref(struct context_ref *ctx, const void *msg, uint32_t msglen)  ;


/*----------------------------------------------------*/
/*final round*/
void whirlpool_final_ref(struct context_ref *pointer, unsigned char *result);

/*----------------------------------------------------*/
#endif /* whirlpool_H_ */
