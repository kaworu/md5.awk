/*
 * A small C program to generate the orlookup table code used by md5.awk.
 *
 * code and idea come from http://stackoverflow.com/a/28332394.
 */
#include <stdint.h>
#include <stdio.h>

static const int orlookup[256] = {
#define C4(a,b) ((a)|(b)), ((a)|(b+1)), ((a)|(b+2)), ((a)|(b+3))
#define L(a) C4(a,0), C4(a,4), C4(a,8), C4(a,12)
#define L4(a) L(a), L(a+1), L(a+2), L(a+3)
    L4(0), L4(4), L4(8), L4(12)
#undef C4
#undef L
#undef L4
};

int
main(int argc, char **argv)
{
	for (int i = 0; i < 256; i++)
		(void)printf("orlookup[%d] = %d;\n", i, orlookup[i]);
	return (0);
}
