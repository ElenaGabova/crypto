#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>

#include "aes_output_ref.h"
#include "sbox.h"
void
show_key_schedule()
{
	unsigned char key128[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
 	};

	 unsigned char key192[] = {
		0x00, 0x01, 0x02, 0x03, 
		0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0a, 0x0b, 
		0x0c, 0x0d, 0x0e, 0x0f, 
		0x10, 0x11, 0x12, 0x13, 
		0x14, 0x15, 0x16, 0x17  };

	unsigned char key256[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f  };

	unsigned char *key[] = { key128, key192, key256 };
        char *key_str[] = { "key128", "key192", "key256" };
        unsigned int key_type[] = {  BITS_128, BITS_192, BITS_256 };
        struct aes_context *ctx;

	for (int i = 0; i < 3; i++) {
		printf("Testing: %s\n", key_str[i]);
		ctx = aes_context_new();
		aes_set_key(ctx, key[i], key_type[i]);
		aes_context_free(ctx);
	}
}

void test_lib()
{
	unsigned char encrypt[16];
	unsigned char decrypt[16];
	
	unsigned char input[] = {
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff };

	/*Реализован пример AES-128 (Nk=4, Nr=10) со стр. 39*/
	unsigned char key128[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f };

	/*Реализован пример AES-192 (Nk=6, Nr=12) со стр. 42*/
	unsigned char key192[] = {
		0x00, 0x01, 0x02, 0x03, 
		0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0a, 0x0b, 
		0x0c, 0x0d, 0x0e, 0x0f, 
		0x10, 0x11, 0x12, 0x13, 
		0x14, 0x15, 0x16, 0x17 };

 	/*Реализован пример AES-256 (Nk=8, Nr=14) со стр. 46*/
	unsigned char key256[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f  };


	unsigned char out128[] = {
                0x69, 0xc4, 0xe0, 0xd8,
		0x6a, 0x7b, 0x04, 0x30,
                0xd8, 0xcd, 0xb7, 0x80,
		0x70, 0xb4, 0xc5, 0x5a };

        unsigned char out192[] = {
                0xdd, 0xa9, 0x7c, 0xa4,
		0x86, 0x4c, 0xdf, 0xe0,
                0x6e, 0xaf, 0x70, 0xa0,
		0xec, 0x0d, 0x71, 0x91 };

        unsigned char out256[] = {
                0x8e, 0xa2, 0xb7, 0xca,
		0x51, 0x67, 0x45, 0xbf,
                0xea, 0xfc, 0x49, 0x90,
		0x4b, 0x49, 0x60, 0x89 };
	
	unsigned char *key[] = { key128, key192, key256 };
        char *key_str[] = { "key128", "key192", "key256" };
        unsigned int key_type[] = {  BITS_128, BITS_192, BITS_256 };
        struct aes_context *ctx;
	
	for (int i = 0; i < 3; i++) {
                printf("\nState: %s\n\n", key_str[i]);
                ctx = aes_context_new();

		printf("KEY: ");
                aes_set_key(ctx, key[i], key_type[i]);
		
		printf("CIPHER (ENCRYPT): \n");
                aes_encrypt(ctx, input, encrypt);

                printf("\nINVERSE CIPHER (DECRYPT): \n");
                aes_decrypt(ctx, encrypt, decrypt);

                aes_context_free(ctx);
        }
	aes_context_free(ctx);
}


int main (int argc, char *argv[])
{	show_key_schedule();
	int show_vec = 0,show_galois = 0, show_ksch = 0, show_sbox = 0;
	for (int i = 1; i < argc && argv[i][0] == '-'; i++) {
		switch (argv[i][1]) {
	
				case 'g':
					show_galois++;
					break;
				case 'k':
					show_ksch++;
					break;
				case 's':
					show_sbox++;
					break;
				default:

			printf("unknown option -%c\n", argv[i][1]);

			printf("Usage: %s [OPTIONS]\n", argv[0]);
			exit(1);	
		}
	}
	
	if (show_vec) 
		test_lib();
	
	if (show_ksch)
		show_key_schedule();
	
	if (show_sbox)
		 sbox_print();
		 
	 test_lib();
	
	return (0); 
}

