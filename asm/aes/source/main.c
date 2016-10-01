#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "../include/openssl/rand.h"
#include "../include/openssl/aes.h"
#include "../include/openssl/evp.h"
#include "../include/aes.h"
#include "../include/aes_slow.h"
#include "../include/aes_slou.h"
#include "../include/aes_asmv.h"
#include "../include/aes_cbc.h"

static void
usage(const char *name)
{
	fprintf(stderr,
	        "Usage: %s [OPTION...]\n"
	        "  -f FILENAME  Use file for tests\n"
	        "               Can't be used together with -s option\n"
	        "  -s STR       Use string STR for tests\n"
	        "               Can't be used together with -f option\n"
	        "  -h           Show this usage and exit\n",
	        name);

	exit(EXIT_FAILURE);
}

static void
parse_opts(int argc, char **argv, char **pfilename, char **pstr, int *pquiet)
{
	if (argc < 2)
		usage(argv[0]);

	int opt;

	*pfilename = NULL;
	*pstr = NULL;
	*pquiet = 0;

	while ((opt = getopt(argc, argv, "f:s:qh")) != -1)
		switch (opt) {
		case 'f':
			*pfilename = optarg;
			break;
		case 's':
			*pstr = optarg;
			break;
		case 'q':
			*pquiet = 1;
			break;
		case 'h':
			usage(argv[0]);
			break;
		default:
			usage(argv[0]);
			break;
		}

	if ((*pfilename != NULL && *pstr != NULL) ||
	        (*pfilename == NULL && *pstr == NULL))
		usage(argv[0]);
}

static size_t
loadfile(const char *filename, char **out)
{
	int fd;
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr,
		        "Error during opening file %s\n", filename);
		exit(EXIT_FAILURE);
	}

	off_t off;
	off = lseek(fd, (off_t) 0, SEEK_END);
	if (off < 0) {
		fprintf(stderr,
		        "Error during processing file %s\n", filename);
		exit(EXIT_FAILURE);
	}

	size_t filesize;
	filesize = (size_t) off;

	*out = malloc((size_t) filesize);
	if (*out == NULL) {
		fprintf(stderr,
		        "Can't allocate %u bytes in memory\n", filesize);
		exit(EXIT_FAILURE);
	}

	off = lseek(fd, (off_t) 0, SEEK_SET);
	if (off < 0) {
		fprintf(stderr,
		        "Error during processing file %s\n", filename);
		exit(EXIT_FAILURE);
	}

	ssize_t rb;
	rb = read(fd, *out, filesize);
	if (rb < 0) {
		fprintf(stderr,
		        "Error during loading file %s\n", filename);
		exit(EXIT_FAILURE);
	}

	return (size_t) rb;
}

static void
printhex(uint8_t *a, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		printf("%02X", a[i]);
}

static double
test_aes_cbc_ossl(const unsigned char *plain, size_t len,
        const unsigned char *key, size_t key_len, unsigned char *iv_enc,
        unsigned char *iv_dec, unsigned char *enc, size_t enc_len,
        unsigned char *dec)
{
	clock_t c;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	int l, m;

	switch (key_len) {
		case 128:
			cipher = EVP_aes_128_cbc();
			break;
		case 192:
			cipher = EVP_aes_192_cbc();
			break;
		case 256:
			cipher = EVP_aes_256_cbc();
			break;
		default:
			fprintf(stderr,
			        "Invalid key len %d\n", key_len);
			exit(EXIT_FAILURE);
			break;
	}

	c = clock();

	EVP_CipherInit(&ctx, cipher, key, iv_enc, 1);
	EVP_CipherUpdate(&ctx, enc, &l, plain, len);
	EVP_CipherFinal(&ctx, enc + l, &m);
	EVP_CipherInit(&ctx, cipher, key, iv_dec, 0);
	EVP_CipherUpdate(&ctx, dec, &l, enc, enc_len);
	EVP_CipherFinal(&ctx, dec + l, &m);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static double
test_aes_cbc_ref(const unsigned char *plain, size_t len,
        const unsigned char *key, size_t key_len, unsigned char *iv_enc,
        unsigned char *iv_dec, unsigned char *enc, size_t enc_len,
        unsigned char *dec)
{
	clock_t c;
	struct aes_context ctx;
	struct aes_cbc cbc;
	aes_key_len key_l;
	size_t l, m;

	switch (key_len) {
		case 128:
			key_l = BITS_128;
			break;
		case 192:
			key_l = BITS_192;
			break;
		case 256:
			key_l = BITS_256;
			break;
		default:
			fprintf(stderr,
			        "Invalid key len %d\n", key_len);
			exit(EXIT_FAILURE);
			break;
	}

	c = clock();

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_encrypt, &ctx, CBC_ENCRYPT, iv_enc);
	aes_cbc_update(&cbc, enc, &l, plain, len);
	aes_cbc_final(&cbc, enc + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_decrypt, &ctx, CBC_DECRYPT, iv_dec);
	aes_cbc_update(&cbc, dec, &l, enc, enc_len);
	aes_cbc_final(&cbc, dec + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static double
test_aes_cbc_slow(const unsigned char *plain, size_t len,
        const unsigned char *key, size_t key_len, unsigned char *iv_enc,
        unsigned char *iv_dec, unsigned char *enc, size_t enc_len,
        unsigned char *dec)
{
	clock_t c;
	struct aes_context ctx;
	struct aes_cbc cbc;
	aes_key_len key_l;
	size_t l, m;

	switch (key_len) {
		case 128:
			key_l = BITS_128;
			break;
		case 192:
			key_l = BITS_192;
			break;
		case 256:
			key_l = BITS_256;
			break;
		default:
			fprintf(stderr,
			        "Invalid key len %d\n", key_len);
			exit(EXIT_FAILURE);
			break;
	}

	c = clock();

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_encrypt_slow, &ctx, CBC_ENCRYPT, iv_enc);
	aes_cbc_update(&cbc, enc, &l, plain, len);
	aes_cbc_final(&cbc, enc + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_decrypt_slow, &ctx, CBC_DECRYPT, iv_dec);
	aes_cbc_update(&cbc, dec, &l, enc, enc_len);
	aes_cbc_final(&cbc, dec + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static double
test_aes_cbc_slou(const unsigned char *plain, size_t len,
        const unsigned char *key, size_t key_len, unsigned char *iv_enc,
        unsigned char *iv_dec, unsigned char *enc, size_t enc_len,
        unsigned char *dec)
{
	clock_t c;
	struct aes_context ctx;
	struct aes_cbc cbc;
	aes_key_len key_l;
	size_t l, m;

	switch (key_len) {
		case 128:
			key_l = BITS_128;
			break;
		case 192:
			key_l = BITS_192;
			break;
		case 256:
			key_l = BITS_256;
			break;
		default:
			fprintf(stderr,
			        "Invalid key len %d\n", key_len);
			exit(EXIT_FAILURE);
			break;
	}

	c = clock();

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_encrypt_slou, &ctx, CBC_ENCRYPT, iv_enc);
	aes_cbc_update(&cbc, enc, &l, plain, len);
	aes_cbc_final(&cbc, enc + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_decrypt_slou, &ctx, CBC_DECRYPT, iv_dec);
	aes_cbc_update(&cbc, dec, &l, enc, enc_len);
	aes_cbc_final(&cbc, dec + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static double
test_aes_cbc_asmv(const unsigned char *plain, size_t len,
        const unsigned char *key, size_t key_len, unsigned char *iv_enc,
        unsigned char *iv_dec, unsigned char *enc, size_t enc_len,
        unsigned char *dec)
{
	clock_t c;
	struct aes_context ctx;
	struct aes_cbc cbc;
	aes_key_len key_l;
	size_t l, m;

	switch (key_len) {
		case 128:
			key_l = BITS_128;
			break;
		case 192:
			key_l = BITS_192;
			break;
		case 256:
			key_l = BITS_256;
			break;
		default:
			fprintf(stderr,
			        "Invalid key len %d\n", key_len);
			exit(EXIT_FAILURE);
			break;
	}

	c = clock();

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_encrypt_asmv, &ctx, CBC_ENCRYPT, iv_enc);
	aes_cbc_update(&cbc, enc, &l, plain, len);
	aes_cbc_final(&cbc, enc + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	aes_context_init(&ctx);
	aes_set_key(&ctx, key, key_l);
	aes_cbc_init(&cbc, aes_decrypt_asmv, &ctx, CBC_DECRYPT, iv_dec);
	aes_cbc_update(&cbc, dec, &l, enc, enc_len);
	aes_cbc_final(&cbc, dec + l, &m);
	aes_cbc_clean(&cbc);
	aes_context_clean(&ctx);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static void
test_aes_cbc(char *str, size_t size)
{
	double t;
	size_t key_len, enc_len;
	unsigned char *key, *iv, *iv_enc, *iv_dec, *enc_ossl, *enc, *dec;

	for (key_len = 128; key_len < 320; key_len += 64) {
		printf("\nTesting AES-CBC-%d\n", key_len);

		key = malloc(sizeof(*key) * key_len / 8);
		iv = malloc(sizeof(*iv) * AES_BLOCK_SIZE);
		iv_enc = malloc(sizeof(*iv_enc) * AES_BLOCK_SIZE);
		iv_dec = malloc(sizeof(*iv_dec) * AES_BLOCK_SIZE);
		enc_len = ((size + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) *
		        AES_BLOCK_SIZE;
		enc_ossl = calloc(sizeof(*enc_ossl) * enc_len, 1);
		enc = calloc(sizeof(*enc) * enc_len, 1);
		dec = calloc(sizeof(*dec) * enc_len, 1);
		if (key == NULL || iv == NULL || iv_enc == NULL ||
		        iv_dec == NULL || enc_ossl == NULL ||
			enc == NULL || dec == NULL) {
			fprintf(stderr,
			        "Can't allocate enough memory for testing\n");
			exit(EXIT_FAILURE);
		}

		if (RAND_bytes(key, key_len / 8) != 1) {
			fprintf(stderr,
			        "Can't initialize key with random bytes\n");
			exit(EXIT_FAILURE);
		}

		printf("Using random key: ");
		printhex(key, key_len / 8);

		if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
			fprintf(stderr,
			        "Can't initialize IV with random bytes\n");
			exit(EXIT_FAILURE);
		}

		printf("\nUsing random IV:  ");
		printhex(iv, AES_BLOCK_SIZE);

		printf("\nOSSL: ");

		memcpy(iv_enc, iv, AES_BLOCK_SIZE);
		memcpy(iv_dec, iv, AES_BLOCK_SIZE);

		t = test_aes_cbc_ossl((const unsigned char *) str, size,
		        (const unsigned char *) key, key_len, iv_enc, iv_dec,
		        enc_ossl, enc_len, dec);

		if (memcmp(str, dec, size) == 0)
			printf("plain and decoded messages are the same, ");
		else
			printf("plain and decoded messages are not the same, ");

		printf("%f\n", t);

		printf("REF:  ");

		memcpy(iv_enc, iv, AES_BLOCK_SIZE);
		memcpy(iv_dec, iv, AES_BLOCK_SIZE);

		t = test_aes_cbc_ref((const unsigned char *) str, size,
		        (const unsigned char *) key, key_len, iv_enc, iv_dec,
		        enc, enc_len, dec);

		if (memcmp(str, dec, size) == 0) {
			printf("plain and decoded messages are the same, ");
			if (memcmp(enc, enc_ossl, enc_len) == 0) {
				printf("encoded message is the same as of "
				        "OSSL's one, ");
			} else {
				printf("but encoded message is not the same "
				        "as of OSSL's one\n");
				printf("\tENC REF [32] = ");
				printhex(enc, 32);
				printf("\n\tENC OSSL[32] = ");
				printhex(enc_ossl, 32);
				printf("\n");
			}

		} else {
			printf("plain and decoded messages are not the same, ");
		}

		printf("%f\n", t);

		printf("SLOW: ");

		memcpy(iv_enc, iv, AES_BLOCK_SIZE);
		memcpy(iv_dec, iv, AES_BLOCK_SIZE);

		t = test_aes_cbc_slow((const unsigned char *) str, size,
		        (const unsigned char *) key, key_len, iv_enc, iv_dec,
		        enc, enc_len, dec);

		if (memcmp(str, dec, size) == 0) {
			printf("plain and decoded messages are the same, ");
			if (memcmp(enc, enc_ossl, enc_len) == 0) {
				printf("encoded message is the same as of "
				        "OSSL's one, ");
			} else {
				printf("but encoded message is not the same "
				        "as of OSSL's one\n");
				printf("\tENC SLOW[32] = ");
				printhex(enc, 32);
				printf("\n\tENC OSSL[32] = ");
				printhex(enc_ossl, 32);
				printf("\n");
			}

		} else {
			printf("plain and decoded messages are not the same, ");
		}

		printf("%f\n", t);

		printf("SLOU: ");

		memcpy(iv_enc, iv, AES_BLOCK_SIZE);
		memcpy(iv_dec, iv, AES_BLOCK_SIZE);

		t = test_aes_cbc_slou((const unsigned char *) str, size,
		        (const unsigned char *) key, key_len, iv_enc, iv_dec,
		        enc, enc_len, dec);

		if (memcmp(str, dec, size) == 0) {
			printf("plain and decoded messages are the same, ");
			if (memcmp(enc, enc_ossl, enc_len) == 0) {
				printf("encoded message is the same as of "
				        "OSSL's one, ");
			} else {
				printf("but encoded message is not the same "
				        "as of OSSL's one\n");
				printf("\tENC SLOU[32] = ");
				printhex(enc, 32);
				printf("\n\tENC OSSL[32] = ");
				printhex(enc_ossl, 32);
				printf("\n");
			}

		} else {
			printf("plain and decoded messages are not the same, ");
		}

		printf("%f\n", t);
		printf("ASMV: ");

		memcpy(iv_enc, iv, AES_BLOCK_SIZE);
		memcpy(iv_dec, iv, AES_BLOCK_SIZE);

		t = test_aes_cbc_asmv((const unsigned char *) str, size,
		        (const unsigned char *) key, key_len, iv_enc, iv_dec,
		        enc, enc_len, dec);

		if (memcmp(str, dec, size) == 0) {
			printf("plain and decoded messages are the same, ");
			if (memcmp(enc, enc_ossl, enc_len) == 0) {
				printf("encoded message is the same as of "
				        "OSSL's one, ");
			} else {
				printf("but encoded message is not the same "
				        "as of OSSL's one\n");
				printf("\tENC ASMV[32] = ");
				printhex(enc, 32);
				printf("\n\tENC OSSL[32] = ");
				printhex(enc_ossl, 32);
				printf("\n");
			}

		} else {
			printf("plain and decoded messages are not the same, ");
		}

		printf("%f\n", t);

		free(key);
		free(iv);
		free(enc_ossl);
		free(dec);
	}
}

int main(int argc, char **argv)
{
	char *filename;
	char *str;
	int quiet;
	size_t size;

	parse_opts(argc, argv, &filename, &str, &quiet);

	if (filename != NULL) {
		size = loadfile(filename, &str);
		if (!quiet)
			printf("Using filename %s of %u bytes size\n",
			        filename, size);
	} else {
		size = strlen(str);
		if (!quiet)
			printf("Using string \"%s\" with length %u\n",
			        str, size);
	}

	test_aes_cbc(str, size);

	return EXIT_SUCCESS;
}
