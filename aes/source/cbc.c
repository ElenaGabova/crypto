#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "aes_ref.h"
#include "aes_cbc_ref.h"

#define BLOCK_SIZE 1024

long get_file_size(FILE *fp)
{  
	fseek(fp,0,SEEK_END);
	return ftell(fp); 
}

int
main(int argc, char *argv[])
{
	FILE *finput, *foutput;
	struct aes_cbc cbc;
	struct aes_context ctx;
	unsigned char key[] = 
		{ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
	unsigned char iv[BLOCK_NBYTES] =
		{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char buf[BLOCK_SIZE];
	unsigned char outbuf[BLOCK_SIZE + BLOCK_NBYTES];
	unsigned int n, read_cnt, write_cnt;
	void (*codec)(void *, const void *, void *);
	int encr;
	char *s;
	long file_size;

	encr = 1;
		
	if (argc < 2) {
		printf("Usage: %s <file> [e|d]\n", argv[0]);
		exit(1);
	}
	encr = 1;	/*Устанавливаем режим шифрования по умолчанию*/
	if (argc >= 3) {
		if (strncmp(argv[2], "e", 1) == 0) /*Если 2 аргумент е, устанавливаем режим шифрования*/
			encr = 1;
		else if (strncmp(argv[2], "d", 1) == 0)   /*Если 2 аргумент d, устанавливаем режим дешифрования*/
			encr = 0;

	}

	codec = encr ? aes_encrypt : aes_decrypt;
	finput = fopen(argv[1], "r+");
	if (finput == NULL)
		exit(1);

	asprintf(&s, "%s.dat", argv[1]);
	foutput = fopen(s, "w+");
	if (foutput == NULL)
		exit(1);
	ftruncate(fileno(foutput), 0); /*Очищаем файл foutput*/
	if (codec == aes_encrypt) {
		file_size = get_file_size(finput); /*Получаем размер файла finput*/
	}
	else {
	  fseek(finput , -8 ,SEEK_END ); 
	  fread(&file_size, sizeof(long), 1, finput);	/*Считываем размер файла foutput*/
	  ftruncate(fileno(finput), get_file_size(finput) - 8); /*Удаляем размер файла из finput*/
	}
	rewind(finput);
	free(s);

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, BITS_256);

	aes_cbc_init(&cbc, (void (*)(void*, const void*, void*)) codec, &ctx, encr, iv);

	read_cnt = write_cnt = 0;

	while (!ferror(finput)) {
		int res;

		res = fread(buf, 1, sizeof(buf), finput); 

		if (res > 0) {
			read_cnt += res;
			aes_cbc_update(&cbc, outbuf, &n, buf, res);	/*увиличиваем количество считанных байт, и выполняем нужную процедуру*/
			
write_again:
			res = fwrite(outbuf, 1, n, foutput);
			if (res != n) {
				if (ferror(foutput)) {
					if (errno == EINTR)
						goto write_again;
					fprintf(stderr, "partial write on foutput: %s\n", strerror(errno));
					clearerr(foutput);
				}
			}
			write_cnt += n;
		}

		if (feof(finput)) {
			aes_cbc_final(&cbc, outbuf, &n);

			if (n > 0)
				res = fwrite(outbuf, 1, BLOCK_NBYTES, foutput);
			write_cnt += n;
			break;
		}
	}
	if (encr == 1) 
		fwrite(&file_size, sizeof(long), 1, foutput);	/*Дописываем размер файла finput в зашифрованный foutput*/
	else {
		rewind(foutput);
		ftruncate(fileno(foutput), file_size);	/*Уменьшаем размер расшифрованого файла*/
	}
	if (write_cnt != read_cnt)
		fprintf(stderr, "write_cnt=%u read_cnt=%u\n", write_cnt, read_cnt);
	else 
		printf("the operation is successful\n");
	fclose(foutput);
	fclose(finput);

	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	return 0;
}

