/*
 * Very simple but very effective user-space memory tester.
 * Originally by Simon Kirby <sim@stormix.com> <sim@neato.org>
 * Version 2 by Charles Cazabon <memtest@discworld.dyndns.org>
 * Version 3 not publicly released.
 * Version 4 rewrite:
 * Copyright (C) 2004 Charles Cazabon <memtest@discworld.dyndns.org>
 * Copyright (C) 2004 - 2014 Tony Scaminaci (Macintosh ports)
 * Licensed under the terms of the GNU General Public License version 2 (only).
 * See the file COPYING for details.
 */

// Macro definitions for handling 32/64 bit platforms at compile time

#include <limits.h>

#define rand32() ((unsigned int) rand() | ( (unsigned int) rand() << 16))

#if (ULONG_MAX == 4294967295UL)
    #define rand_ul() rand32()
    #define UL_ONEBITS 0xffffffff
    #define UL_LEN 32
    #define CHECKERBOARD1 0x55555555
    #define CHECKERBOARD2 0xaaaaaaaa
    #define UL_BYTE(x) ((x | x << 8 | x << 16 | x << 24))
#elif (ULONG_MAX == 18446744073709551615ULL)
    #define rand64() (((ul) rand32()) << 32 | ((ul) rand32()))
    #define rand_ul() rand64()
    #define UL_ONEBITS 0xffffffffffffffffUL
    #define UL_LEN 64
    #define CHECKERBOARD1 0x5555555555555555
    #define CHECKERBOARD2 0xaaaaaaaaaaaaaaaa
    #define UL_BYTE(x) (((ul)x | (ul)x<<8 | (ul)x<<16 | (ul)x<<24 | (ul)x<<32 | (ul)x<<40 | (ul)x<<48 | (ul)x<<56))
#else
    #error long on this platform is not 32 or 64 bits
#endif

// Mask bit definitions for command line arguments
// Tony Scaminaci (updated 1/2007)

#define USE_LOG_FILE		0x00000001
#define QUICK_FLAG			0x00000002
#define RESERVED_2			0X00000004
#define RESERVED_3			0X00000008
#define NUMBER_OF_PASSES	0x00000FF0
#define	TEST_SIZE_MB		0xFFFFF000

// Mask bits used in Linear PRN test
// Tony Scaminaci 10/2006

#define Tap63Mask	0x4000000000000000
#define Tap1Mask	0x0000000000000001

// Custom type definitions

typedef unsigned long ul;
typedef unsigned long long ull;
typedef unsigned long volatile ulv;

struct test
{
	char *name;
	int (*fp)();
};

// Test routine declarations

int test_stuck_address(unsigned long volatile *buf, int arg_list, size_t count);					// Linear stuck address test - full buffer
int test_linear_prn(unsigned long volatile *buf, int arg_list, size_t count, time_t timestamp);		// Linear pseudorandom test - full buffer
int test_random_value(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_xor_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_sub_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_mul_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_div_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_or_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_and_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_seqinc_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_solidbits_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_checkerboard_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_blockseq_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_walkbits0_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_walkbits1_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_bitspread_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);
int test_bitflip_comparison(unsigned long volatile *bufa, unsigned long volatile *bufb, int arg_list, size_t count);

