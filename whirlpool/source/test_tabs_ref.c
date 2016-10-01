#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "galois.h"
#include "whirlpool_ref.h"



int main(int argc, char *argv[]) {


	struct rusage ru, rs;
	int i;

	uint8_t M0[64] = {
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		8, 7, 6, 5, 4, 3, 2, 1
	};
	uint8_t M1[64] = {
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		8, 7, 6, 5, 4, 3, 2, 1
	};
	uint8_t M2[64] = {
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		8, 7, 6, 5, 4, 3, 2, 1
	};
	uint8_t M3[64] = {
		1, 1, 1, 1, 1, 1, 1, 1,
		2, 2, 2, 2, 2, 2, 2, 2,
		3, 3, 3, 3, 3, 3, 3, 3,
		4, 4, 4, 4, 4, 4, 4, 4,
		5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6,
		7, 7, 7, 7, 7, 7, 7, 7,
		8, 8, 8, 8, 8, 8, 8, 8
	};

	galois_init_tables();
	
	getrusage(RUSAGE_SELF, &ru);
	rs = ru;

	mix_rows_slow((uint32_t *)M0);
	mix_rows((uint32_t *)M1);

	printf("M0 mix_rows_slow\n");

	for (i = 0; i < 64; ) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       M0[i], M0[i+1], M0[i+2], M0[i+3],
		       M0[i+4], M0[i+5], M0[i+6], M0[i+7]);
		i += 8;
	}

	printf("\n");
	printf("M1 mix_rows\n");

	for (i = 0; i < 64; ) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       M1[i], M1[i+1], M1[i+2], M1[i+3],
		       M1[i+4], M1[i+5], M1[i+6], M1[i+7]);
		i += 8;
	}

	printf("\n");
	printf("\n");

	shift_columns(M2);
	printf("M2 shift_columns\n");

	for (i = 0; i < 64; ) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       M3[i], M3[i+1], M3[i+2], M3[i+3],
		       M3[i+4], M3[i+5], M3[i+6], M3[i+7]);
		i += 8;
	}
	printf("\n");


	for (i = 0; i < 1000000; i++) {
		mix_rows((uint32_t *)M1);
	}

	getrusage(RUSAGE_SELF, &ru);
	ru.ru_utime.tv_sec -= rs.ru_utime.tv_sec;
	ru.ru_utime.tv_usec -= rs.ru_utime.tv_usec;
	if (ru.ru_utime.tv_usec < 0) {
		ru.ru_utime.tv_usec += 1000000;
		ru.ru_utime.tv_sec -= 1;
	}

	printf("FAST Mixing 1000000 matrices: %lu sec %lu usec\n", ru.ru_utime.tv_sec, ru.ru_utime.tv_usec);

	printf("\n");

	getrusage(RUSAGE_SELF, &ru);
	rs = ru;

	mix_rows_slow((uint32_t *)M1);

	for (i = 0; i < 1000000; i++) {
		mix_rows((uint32_t *)M1);
	}

	getrusage(RUSAGE_SELF, &ru);
	ru.ru_utime.tv_sec -= rs.ru_utime.tv_sec;
	ru.ru_utime.tv_usec -= rs.ru_utime.tv_usec;
	if (ru.ru_utime.tv_usec < 0) {
		ru.ru_utime.tv_usec += 1000000;
		ru.ru_utime.tv_sec -= 1;
	}

	printf("SLOW Mixing 1000000 matrices: %lu sec %lu usec\n", ru.ru_utime.tv_sec, ru.ru_utime.tv_usec);

	for (i = 0; i < 64; ) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       M0[i], M0[i+1], M0[i+2], M0[i+3],
		       M0[i+4], M0[i+5], M0[i+6], M0[i+7]);
		i += 8;
	}
	printf("\n");

	shift_columns((uint32_t*)M2);

	for (i = 0; i < 64; ) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       M2[i], M2[i+1], M2[i+2], M2[i+3],
		       M2[i+4], M2[i+5], M2[i+6], M2[i+7]);
		i += 8;
	}
	printf("\n");

	printf("M1 reference\n");

	for (i = 0; i < 64; ) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       M1[i], M1[i+1], M1[i+2], M1[i+3],
		       M1[i+4], M1[i+5], M1[i+6], M1[i+7]);
		i += 8;
	}
	printf("\n");

	return 0;
}



