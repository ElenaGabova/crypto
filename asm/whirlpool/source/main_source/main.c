#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "../include/nessie.h"
#include "../include/openssl/evp.h"
#include "../include/whirlpool_ref.h"
#include "../include/whirlpool_slow.h"
#include "../include/whirlpool_asmv.h"

static void
usage(const char *name)
{
	fprintf(stderr,
	        "Usage: %s [OPTION...]\n"
		"  -q           Show only hashes for REFO, REF, SLOW and\n"
		"               ASMV implementations\n"
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
		        "Can't allocate %lu bytes in memory\n", filesize);
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

static double
test_whirlpool_refo(char *str, size_t size, uint8_t *dgst)
{
	NESSIEstruct ns;
	clock_t c;

	NESSIEinit(&ns);

	c = clock();
	NESSIEadd(str, 8 * size, &ns);
	NESSIEfinalize(&ns, dgst);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static double
test_whirlpool_ossl(char *str, size_t size, uint8_t *dgst)
{
	EVP_MD_CTX ctx;
	unsigned int m;
	clock_t c;


	c = clock();
	EVP_DigestInit(&ctx, EVP_whirlpool());
	EVP_DigestUpdate(&ctx, str, size);
	EVP_DigestFinal(&ctx, dgst, &m);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static double
test_whirlpool_ref(char *str, size_t size, uint8_t *dgst)
{
	struct context_ref ctx;
	clock_t c;

	whirlpool_init_ref(&ctx);

	c = clock();
	whirlpool_update_ref(&ctx, str, (uint32_t) size);
	whirlpool_final_ref(&ctx, dgst);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static double
test_whirlpool_slow(char *str, size_t size, uint8_t *dgst)
{
	struct context_slow ctx;
	clock_t c;

	whirlpool_init_slow(&ctx);

	c = clock();
	whirlpool_update_slow(&ctx, str, (uint32_t) size);
	whirlpool_final_slow(&ctx, dgst);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}


static double
test_whirlpool_asmv(char *str, size_t size, uint8_t *dgst)
{
	struct context_asmv ctx;
	clock_t c;

	whirlpool_init_asmv(&ctx);

	c = clock();
	whirlpool_update_asmv(&ctx, str, (uint32_t) size);
	whirlpool_final_asmv(&ctx, dgst);

	return ((double) clock() - c) / CLOCKS_PER_SEC;
}

static void
printhex(uint8_t *a, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		printf("%02X", a[i]);
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
			printf("Using filename %s of %lu bytes size\n",
			        filename, size);
	} else {
		size = strlen(str);
		if (!quiet)
			printf("Using string \"%s\" with length %lu\n",
			        str, size);
	}

	double t;

	uint8_t refo_dgst[DIGESTBYTES];

	t = test_whirlpool_refo(str, size, refo_dgst);
	if (quiet) {
		printhex(refo_dgst, DIGESTBYTES);
		printf("\n");
	} else {
		printf("REFO ");
		printhex(refo_dgst, DIGESTBYTES);
		printf(" %f seconds\n", t);
	}

	uint8_t ossl_dgst[BLOCK_NBYTES];

	t = test_whirlpool_ossl(str, size, ossl_dgst);
	if (quiet) {
		printhex(ossl_dgst, BLOCK_NBYTES);
		printf("\n");
	} else {
		printf("OSSL ");
		printhex(ossl_dgst, BLOCK_NBYTES);
		printf(" %f seconds\n", t);
	}

	uint8_t ref_dgst[BLOCK_NBYTES];

	t = test_whirlpool_ref(str, size, ref_dgst);
	if (quiet) {
		printhex(ref_dgst, BLOCK_NBYTES);
		printf("\n");
	} else {
		printf("REF  ");
		printhex(ref_dgst, BLOCK_NBYTES);
		printf(" %f seconds\n", t);
	}

	uint8_t slow_dgst[BLOCK_NBYTES];

	t = test_whirlpool_slow(str, size, slow_dgst);
	if (quiet) {
		printhex(slow_dgst, BLOCK_NBYTES);
		printf("\n");
	} else {
		printf("SLOW ");
		printhex(slow_dgst, BLOCK_NBYTES);
		printf(" %f seconds\n", t);
	}


	uint8_t asmv_dgst[BLOCK_NBYTES];

	t = test_whirlpool_asmv(str, size, asmv_dgst);
	if (quiet) {
		printhex(asmv_dgst, BLOCK_NBYTES);
		printf("\n");
	} else {
		printf("asmv ");
		printhex(asmv_dgst, BLOCK_NBYTES);
		printf(" %f seconds\n", t);
	}

	return EXIT_SUCCESS;
}
