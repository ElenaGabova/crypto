#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "aes_output_slow.h"
#include "aes_cbc_ref.h"
void print_text(unsigned char *text, char *prefix, int len) {    
	int i = 0;

	if (prefix != NULL)
		printf("%s\t  ",prefix);
	while (i < len) {
		
		if ((i >= 10) && i % 16 == 0)
			printf("\n\t\t  ");
		printf("%02x", text[i]);
		i++;
	}
printf("\n");
};

int
main()
{
	unsigned char out[BLOCK_NBYTES * 4];
	unsigned char out2[BLOCK_NBYTES * 4];
	struct aes_context aes_cipher;
	struct aes_cbc cbc_encrypt, cbc_decrypt;
	unsigned int len, tmplen;
	{

		unsigned char key[] = {
			0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
			0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06
		};
		unsigned char iv[] = {
			0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
			0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41
		};
		char *plaintext = "Single block msg";

		aes_context_init(&aes_cipher);
		aes_set_key(&aes_cipher, key, BITS_128);
		aes_cbc_init(&cbc_encrypt, aes_encrypt, &aes_cipher, 1, iv);
		aes_cbc_init(&cbc_decrypt, aes_decrypt, &aes_cipher, 0, iv);
	
		aes_cbc_update(&cbc_encrypt, out, &len, plaintext, strlen(plaintext));
		aes_cbc_final(&cbc_encrypt, out + len, &tmplen);
		len +=tmplen;
		aes_cbc_clean(&cbc_encrypt);

		printf("\n");
		print_text(plaintext, "Plaintext:", len);
		print_text(key, "key:	", sizeof(key));
		print_text(iv, "IV:	", sizeof(iv));
		print_text(out, "Encrypted:", len);
		printf("\n");

		aes_cbc_update(&cbc_decrypt, out2, &len, out, 16);
		aes_cbc_final(&cbc_decrypt, out2 + len, &tmplen);
		len +=tmplen;
		aes_cbc_clean(&cbc_decrypt);
		
		printf("\n");
		print_text(out2, "Decrypted:", len);

		aes_context_clean(&aes_cipher);
	}
	{
		unsigned char key[] = {
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
		};
		unsigned char iv[] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
		};
		unsigned char plaintext[] = {
			0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
			0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
			0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
			0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
		};

		aes_context_init(&aes_cipher);
		aes_set_key(&aes_cipher, key, BITS_128);
		aes_cbc_init(&cbc_encrypt, aes_encrypt, &aes_cipher, 1, iv);
		aes_cbc_init(&cbc_decrypt, aes_decrypt, &aes_cipher, 0, iv);
	
		aes_cbc_update(&cbc_encrypt, out, &len, plaintext,  sizeof(plaintext));
		aes_cbc_final(&cbc_encrypt, out + len, &tmplen);
		len +=tmplen;
		aes_cbc_clean(&cbc_encrypt);

		printf("\n");
		print_text(plaintext, "Plaintext:", sizeof(plaintext));
		print_text(key, "key:	", sizeof(key));
		print_text(iv, "IV:	", sizeof(iv));
		print_text(out, "Encrypted:", len);
		printf("\n");

		aes_cbc_update(&cbc_decrypt, out2, &len, out,  sizeof(plaintext));
		aes_cbc_final(&cbc_decrypt, out2 + len, &tmplen);
		len +=tmplen;
		aes_cbc_clean(&cbc_decrypt);

		printf("\n");
		print_text(out2, "Decrypted:", len);

		aes_context_clean(&aes_cipher);
	}
	return 0;
}
	
