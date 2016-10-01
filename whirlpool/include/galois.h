
#ifndef galois_H_
#define galois_H_


void mix_columns_slow(uint32_t *state[16]);


uint8_t transform_bits(uint8_t u);


void create_sbox();


void galois_init_tables();


void galois_print_tables();


void sub_bytes_slow(uint64_t state[8]);

#endif
