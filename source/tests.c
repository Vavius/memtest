/*
 * Very simple but very effective user-space memory tester.
 * Originally by Simon Kirby <sim@stormix.com> <sim@neato.org>
 * Version 2 by Charles Cazabon <memtest@discworld.dyndns.org>
 * Version 3 not publicly released.
 * Version 4 rewrite:
 * Copyright (C) 2004 Charles Cazabon <memtest@discworld.dyndns.org>
 * Portions Copyright (C) 2005 - 2013 Tony Scaminaci
 * Licensed under the terms of the GNU General Public License version 2 (only).
 * See the file COPYING for details.
 *
 * This file contains the functions for the actual tests, called from the
 * main routine in memtest.c.  See other comments in that file.
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "memtest.h"

// Global variables

extern FILE	*logfile;

char progress[] = "-\\|/";
#define PROGRESSLEN 4
#define PROGRESSOFTEN 600000

/* Function definitions. */

int compare_regions(ulv *bufa, ulv *bufb, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
	  {
        if (bufa[i] != bufb[i])
		{
		  if (sizeof(size_t) == 8)
			{
			  printf("\n\nFAILURE! Data mismatch at local BUFA address 0x%016llx, BUFB address 0x%016llx\n", (ull) (bufa + i), (ull) (bufb + i));
			  printf("BUFA Data: 0x%016llx, BUFB Data: 0x%016llx\n\n", (ull) bufa[i], (ull) bufb[i]);
			  if (logfile != NULL)
				{
				  fprintf(logfile, "\n\nFAILURE! Data mismatch at local BUFA address 0x%016llx, BUFB address 0x%016llx\n", (ull) (bufa + i), (ull) (bufb + i));
				  fprintf(logfile, "BUFA Data: 0x%016llx, BUFB Data: 0x%016llx\n\n", (ull) bufa[i], (ull) bufb[i]);
				  fflush(logfile);
				}
			}
		  else
		    {
			  printf("\n\nFAILURE! Data mismatch at local BUFA address 0x%08lx, BUFB address 0x%08lx\n", (ul) (bufa + i), (ul) (bufb + i));
			  printf("BUFA Data: 0x%08lx, BUFB Data: 0x%08lx\n\n", (ul) bufa[i], (ul) bufb[i]);
			  if (logfile != NULL)
				{
				  fprintf(logfile, "\n\nFAILURE! Data mismatch at local BUFA address 0x%08lx, BUFB address 0x%08lx\n", (ul) (bufa + i), (ul) (bufb + i));
				  fprintf(logfile, "BUFA Data: 0x%08lx, BUFB Data: 0x%08lx\n\n", (ul) bufa[i], (ul) bufb[i]);
				  fflush(logfile);
				}
			}
		  fflush(stdout);
		  return -1;
        }
      }
    return 0;
}

int test_stuck_address(ulv *buf, int arg_list, size_t count)
{
    unsigned int j;
    size_t i;
	unsigned int loops = 16;

	if (arg_list & QUICK_FLAG)	// Check for short test run
	  loops = 4;
	printf("             ");
    fflush(stdout);
    for (j = 0; j < loops; j++)
	{
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("setting %2u of %2u", j+1, loops);
        fflush(stdout);
        for (i = 0; i < count; i++)
		{
            buf[i] = ((j + i) % 2) == 0 ? (ul) &buf[i] : ~((ul) &buf[i]);
        }
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %2u of %2u", j+1, loops);
		fflush(stdout);
        for (i = 0; i < count; i++)
		{
		  if (buf[i] != (((j + i) % 2) == 0 ? (ul) &buf[i] : ~((ul) &buf[i])))
			{
			  if (sizeof(size_t) == 8)
				{
				  printf("\n\nFAILURE! Data mismatch at local address 0x%016llx\n", (ull) (buf + i));
				  printf("Actual Data: 0x%016llx\n\n", (ull) buf[i]);
				  if (logfile != NULL)
					{
					  fprintf(logfile, "\n\nFAILURE! Data mismatch at local address 0x%016llx\n", (ull) (buf + i));
					  fprintf(logfile, "Actual Data: 0x%016llx\n\n", (ull) buf[i]);
					  fflush(logfile);
					}
				}
			  else
				{
				  printf("\n\nFAILURE! Data mismatch at local address 0x%08lx\n", (ul) (buf + i));
				  printf("Actual Data: 0x%08lx\n\n", (ul) buf[i]);
				  if (logfile != NULL)
					{
					  fprintf(logfile, "\n\nFAILURE! Data mismatch at local address 0x%08lx\n", (ul) (buf + i));
					  fprintf(logfile, "Actual Data: 0x%08lx\n\n", (ul) buf[i]);
					  fflush(logfile);
					}
				}
			  fflush(stdout);
			  return -1;
			}
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_linear_prn(ulv *buf, int arg_list, size_t count, time_t TimeStamp)
{
	size_t			i;
	unsigned int	j;
	ull				DoubleTimeStamp;		// 64-bit extended timestamp
	ull				ShiftReg;				// 63-stage maximal-length LFSR
	ull				InitValue;				// Saved state for comparison
	char			TimeBit;				// LSB of shifted time stamp
	char			Tap63Val,Tap1Val;		// Hi and Lo tap values
	char			XORFeedBack;			// XOR'd feedback from register taps
	unsigned int	loops = 16;

	if (arg_list & QUICK_FLAG)                                  // Check for short test run
	  loops = 4;
	DoubleTimeStamp = ((ull)TimeStamp << 32) + (ull)TimeStamp;	// Extend timestamp to 64-bit word
	ShiftReg = 0x39C1AD5CB71E04F9;                              // Initialize 64-bit shift register
	for (i = 0; i < 64; i++)                                    // Randomize shift register based on unique timestamp
	  {
		Tap63Val = (ShiftReg & Tap63Mask) ? 1 : 0;
		Tap1Val = (ShiftReg & Tap1Mask) ? 1 : 0;
		TimeBit = (DoubleTimeStamp >> i) & 1;				// Shift 64-bit timestamp register
		XORFeedBack = Tap63Val ^ Tap1Val ^ TimeBit;
		ShiftReg = (ShiftReg << 1) + (ull)XORFeedBack;		// Shift register and add value combined feedback
	  }
	printf("\b\b\b");
    for (j = 0; j < loops; j++)
	  {
		printf("setting %2u of %2u", j+1, loops);
		fflush(stdout);
		InitValue = ShiftReg;								// Save present register state for comparison
		for (i = 0; i < count; i++)
		  {
			Tap63Val = (ShiftReg & Tap63Mask) ? 1 : 0;
			Tap1Val = (ShiftReg & Tap1Mask) ? 1 : 0;
			XORFeedBack = Tap63Val ^ Tap1Val;
			ShiftReg = (ShiftReg << 1) + (ull)XORFeedBack;
			buf[i] = (size_t) ShiftReg;
		  }
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
		printf("testing %2u of %2u", j+1, loops);
		fflush(stdout);
		ShiftReg = InitValue;								// Restore previously saved value of shift register
		for (i = 0; i < count; i++)
		  {
			Tap63Val = (ShiftReg & Tap63Mask) ? 1 : 0;
			Tap1Val = (ShiftReg & Tap1Mask) ? 1 : 0;
			XORFeedBack = Tap63Val ^ Tap1Val;
			ShiftReg = (ShiftReg << 1) + (ull)XORFeedBack;
			if (buf[i] != (size_t) ShiftReg)
			  {
				if (sizeof(size_t) == 8)
				  {
					printf("\n\nFAILURE! Data mismatch at local address 0x%016llx\n", (ull) (buf + i));
					printf("Expected Data: 0x%016llx, Actual Data: 0x%016llx\n\n", (ull) ShiftReg, (ull) buf[i]);
					if (logfile != NULL)
					  {
						fprintf(logfile, "\n\nFAILURE! Data mismatch at local address  0x%016llx\n", (ull) (buf + i));
						fprintf(logfile, "Expected Data: 0x%016llx, Actual Data: 0x%016llx\n\n", (ull) ShiftReg, (ull) buf[i]);
						fflush(logfile);
					  }
				  }
				else
				  {
					printf("\n\nFAILURE! Data mismatch at local address 0x%08lx\n", (ul) (buf + i));
					printf("Expected Data: 0x%08lx, Actual Data: 0x%08lx\n\n", (ul) ShiftReg,(ul) buf[i]);
					if (logfile != NULL)
					  {
						fprintf(logfile, "\n\nFAILURE! Data mismatch at local address 0x%08lx\n", (ul) (buf + i));
						fprintf(logfile, "Expected Data: 0x%08lx, Actual Data: 0x%08lx\n\n", (ul) ShiftReg, (ul) buf[i]);
						fflush(logfile);
					  }
				  }
				fflush(stdout);
                return -1;
			  }
		  }
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
	  }
    printf("                \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
	return 0;
}

int test_random_value(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    ul j = 0;
    size_t i;

	printf("\b\b");
    fflush(stdout);
    for (i = 0; i < count; i++)
	{
        bufa[i] = bufb[i] = rand_ul();
		if (!(i % PROGRESSOFTEN))
		{
			putchar('\b');
			putchar(progress[++j % PROGRESSLEN]);
            fflush(stdout);
		}
    }
	printf("\b \b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_xor_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++)
	{
        bufa[i] ^= q;
        bufb[i] ^= q;
    }
	printf("\b\b\b   \b\b\b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_sub_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++)
	{
        bufa[i] -= q;
        bufb[i] -= q;
    }
	printf("\b\b\b   \b\b\b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_mul_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++)
	{
        bufa[i] *= q;
        bufb[i] *= q;
    }
	printf("\b\b\b   \b\b\b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_div_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++)
	{
        if (!q)
		{
            q++;
        }
        bufa[i] /= q;
        bufb[i] /= q;
    }
	printf("\b\b\b   \b\b\b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_or_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++)
	{
        bufa[i] |= q;
        bufb[i] |= q;
    }
	printf("\b\b\b   \b\b\b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_and_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++)
	{
        bufa[i] &= q;
        bufb[i] &= q;
    }
	printf("\b\b\b   \b\b\b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_seqinc_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    size_t i;
    ul q = rand_ul();

    for (i = 0; i < count; i++)
	{
        bufa[i] = bufb[i] = (i + q);
    }
	printf("\b\b\b   \b\b\b");
    fflush(stdout);
    return compare_regions(bufa, bufb, count);
}

int test_solidbits_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    unsigned int j;
    ul q;
    size_t i;
	unsigned int loops = 64;

	if (arg_list & QUICK_FLAG)		// Check for short test run
	  loops = 16;
	printf("             ");
    fflush(stdout);
    for (j = 0; j < loops; j++)
	{
	    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        q = (j % 2) == 0 ? UL_ONEBITS : 0;
        printf("setting %2u of %2u", j+1, loops);
        fflush(stdout);
        for (i = 0; i < count; i++)
		{
            bufa[i] = bufb[i] = (i % 2) == 0 ? q : ~q;
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %2u of %2u", j+1, loops);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count))
		{
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_checkerboard_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    unsigned int j;
    ul q;
    size_t i;
	unsigned int loops = 64;

	if (arg_list & QUICK_FLAG)		// Check for short test run
	  loops = 16;
	printf("             ");
    fflush(stdout);
    for (j = 0; j < loops; j++)
	{
	    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        q = (j % 2) == 0 ? CHECKERBOARD1 : CHECKERBOARD2;
        printf("setting %2u of %2u", j+1, loops);
        fflush(stdout);
        for (i = 0; i < count; i++)
		{
            bufa[i] = bufb[i] = (i % 2) == 0 ? q : ~q;
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %2u of %2u", j+1, loops);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count))
		{
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_blockseq_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    unsigned int j;
    size_t i;
	unsigned int loops = 256;

	if (arg_list & QUICK_FLAG)		// Check for short test run
	  loops = 32;
	printf("               ");
    fflush(stdout);
    for (j = 0; j < loops; j++)
	{
	    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("setting %3u of %3u", j+1, loops);
        fflush(stdout);
        for (i = 0; i < count; i++)
		{
            bufa[i] = bufb[i] = (ul) UL_BYTE(j);
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u of %3u", j+1, loops);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count))
		{
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                    \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_walkbits0_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    unsigned int j;
    size_t i;
    unsigned int loops = UL_LEN * 2;

    if (arg_list & QUICK_FLAG)		// Check for short test run
        loops = UL_LEN;
	printf("               ");
    fflush(stdout);
    for (j = 0; j < loops; j++)
	{
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
		printf("setting %3u of %3u", j+1, loops);
        fflush(stdout);
        for (i = 0; i < count; i++)
		{
            if (j < UL_LEN) 
			{ /* Walk it up. */
                bufa[i] = bufb[i] = 0x00000001 << j;
            } else
			{ /* Walk it back down. */
                bufa[i] = bufb[i] = 0x00000001 << (loops - j - 1);
            }
        }
		printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u of %3u", j+1, loops);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count))
		{
            return -1;
        }
    }
	printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                  \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_walkbits1_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    unsigned int j;
    size_t i;
    unsigned int loops = UL_LEN * 2;

    if (arg_list & QUICK_FLAG)		// Check for short test run
        loops = UL_LEN;
	printf("               ");
    fflush(stdout);
    for (j = 0; j < loops; j++)
	{
	    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
		printf("setting %3u of %3u", j+1, loops);
        fflush(stdout);
        for (i = 0; i < count; i++)
		{
            if (j < UL_LEN)
			{ /* Walk it up. */
                bufa[i] = bufb[i] = UL_ONEBITS ^ (0x00000001 << j);
            } else
			{ /* Walk it back down. */
                bufa[i] = bufb[i] = UL_ONEBITS ^ (0x00000001 << (loops - j - 1));
            }
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u of %3u", j+1, loops);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count))
		{
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                  \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_bitspread_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    unsigned int j;
    size_t i;
    unsigned int loops = UL_LEN * 2;

    if (arg_list & QUICK_FLAG)		// Check for short test run
        loops = UL_LEN;
	printf("               ");
    fflush(stdout);
    for (j = 0; j < loops; j++)
	{
	    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("setting %3u of %3u", j+1, loops);
        fflush(stdout);
        for (i = 0; i < count; i++)
		{
            if (j < UL_LEN)
			{ /* Walk it up. */
                bufa[i] = bufb[i] = (i % 2 == 0)
                    ? (0x00000001 << j) | (0x00000001 << (j + 2))
                    : UL_ONEBITS ^ ((0x00000001 << j)
                                    | (0x00000001 << (j + 2)));
            } else
			{ /* Walk it back down. */
                bufa[i] = bufb[i] = (i % 2 == 0)
                    ? (0x00000001 << (loops - 1 - j)) | (0x00000001 << (loops + 1 - j))
                    : UL_ONEBITS ^ (0x00000001 << (loops - 1 - j)
                                    | (0x00000001 << (loops + 1 - j)));
            }
        }
        printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        printf("testing %3u of %3u", j+1, loops);
        fflush(stdout);
        if (compare_regions(bufa, bufb, count))
		{
            return -1;
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                  \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}

int test_bitflip_comparison(ulv *bufa, ulv *bufb, int arg_list, size_t count)
{
    unsigned int j, k;
    ul q;
    size_t i;
    unsigned int K = 8;
    
    if (arg_list & QUICK_FLAG)		// Check for short test run
        K = 2;
	printf("               ");
    fflush(stdout);
    for (k = 0; k < UL_LEN; k++)
	{
        q = 0x00000001 << k;
        for (j = 0; j < K; j++)
		{
    	    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
            q = ~q;
            printf("setting %3u of %3u", k * K + j + 1, UL_LEN * K);
            fflush(stdout);
            for (i = 0; i < count; i++) {
                bufa[i] = bufb[i] = (i % 2) == 0 ? q : ~q;
            }
            printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
            printf("testing %3u of %3u", k * K + j + 1, UL_LEN * K);
            fflush(stdout);
            if (compare_regions(bufa, bufb, count))
			{
                return -1;
            }
        }
    }
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b                  \b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush(stdout);
    return 0;
}
