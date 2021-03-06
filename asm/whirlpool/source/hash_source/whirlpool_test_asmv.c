#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <time.h>    

#include "whirlpool_asmv.h"

#include "file_library.h"


int
main(int argc, char *argv[]) {
	long i, len;
	clock_t t;
	char *msg;
	char *filename = malloc(sizeof(char) * 2048);
  	t = clock();
	struct context_asmv ctx;
	
	
	if (argc > 1){
		if(strcmp(argv[1], "-f") == 0) {
			long n = file_size(argv[2]);
			msg = malloc(sizeof(char) * (n + 1));
			read_from_file(argv[2], msg, n);
			len = n;
			filename = argv[2];
			
		}
		else {
			msg =  malloc(sizeof(char) * 2048);
			msg = argv[1];
			len = strlen(msg);
			filename = msg;
			
		}
		
	}
	else {
		msg =  malloc(sizeof(char) * 2048);
		gets(msg);
		len = strlen(msg);
		filename = msg;
	}
	
	
	unsigned char cp[64];
	
	whirlpool_init_asmv(&ctx);
	memset(cp, 0, sizeof(cp));
	whirlpool_update_asmv(&ctx, msg, len);
	whirlpool_final_asmv(&ctx, cp);

	
	printf("\nWHIRLPOOL_asmv(%s)=\n\t", filename);
	
	for (i = 0; i < 64; ) {
		printf("%02X%02X%02X%02X%02X%02X%02X%02x",
		       cp[i], cp[i+1], cp[i+2], cp[i+3],
		       cp[i+4], cp[i+5], cp[i+6], cp[i+7]);
		i += 8;
		printf("%02X%02X%02X%02X%02X%02X%02X%02x",
		       cp[i], cp[i+1], cp[i+2], cp[i+3],
		       cp[i+4], cp[i+5], cp[i+6], cp[i+7]);
		i += 8;
	if (i == 32) printf("\n\t");
		
	}
 	t = clock() - t;

	printf ("\n\nRuntime (%f seconds)\n\n",
          ((double)t)/CLOCKS_PER_SEC);
	return 0;
}
