#ifndef galoisu_H_
#define galoisu_H_

uint8_t transform_bitsu(uint8_t u);
uint8_t inv_transform_bitsu(uint8_t u);

/* Умножает каждый байт массива на 2 в поле Rijndael */
void g2times(uint8_t *p, size_t n);

#endif /* galoisu_H_ */
