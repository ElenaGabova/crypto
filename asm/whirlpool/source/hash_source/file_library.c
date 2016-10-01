#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


long file_size(char *filename) {

	long bufsize = 0;
	FILE *fp = fopen(filename, "r+");
	
	if (fp != NULL) {
	    if (fseek(fp, 0L, SEEK_END) == 0)
		bufsize = ftell(fp);
	}
	
	fclose(fp);
	
	return bufsize;
}

void read_from_file(char *filename, char *msg, long bufsize) {
	
	FILE *fp = fopen(filename, "r+");
	if (fp != NULL) {
	
	    if (fseek(fp, 0L, SEEK_END) == 0) {


		if (fseek(fp, 0L, SEEK_SET) == 0) { } //ERROR

		size_t newLen = fread(msg, sizeof(char), bufsize, fp);
		
		if (newLen == 0) {
		    fputs("Error reading file", stderr);
		} else {
		    msg[++newLen] = '\0'; 
		}
	    }
	    
	    fclose(fp);
	}
}

