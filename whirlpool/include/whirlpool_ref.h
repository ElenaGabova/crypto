#ifndef whirlpool_H_
#define whirlpool_H_

#include <stdint.h>


  
#define LE32(x)	(x)
#define LE64(x)	(x)
#define R64(x)	((x >> 32) | (x << 32))
#define BLOCK_NBYTES	64
#define WHIRLPOOL_NB  8


struct context{
	uint32_t length[2];
	uint8_t  buffer[64];
	uint64_t state[8];    
} ctx;

/*----------------------------------------------------*/
void whirlpool_hash(uint64_t s[8], const unsigned char buffer[64]);

 
/*----------------------------------------------------*/
/*Init structure*/
void whirlpool_init(struct context *pointer);


/*----------------------------------------------------*/
/*add element to whirlpool structure*/
void whirlpool_update(struct context *ctx, const void *msg, uint32_t msglen)  ;


/*----------------------------------------------------*/
/*final round*/
void whirlpool_final(struct context *pointer, unsigned char *result);


/*----------------------------------------------------*/
/*display array*/
void display(uint8_t array[], int length);


/*----------------------------------------------------*/
#endif /* whirlpool_H_ */
