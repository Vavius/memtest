/*
 * memtest version 4.23
 *
 * Very simple but very effective user-space memory tester.
 * Originally by Simon Kirby <sim@stormix.com> <sim@neato.org>
 * Version 2 by Charles Cazabon <memtest@discworld.dyndns.org>
 * Version 3 not publicly released.
 * Version 4 rewrite:
 * Copyright (C) 2004 Charles Cazabon <memtest@discworld.dyndns.org>
 * Copyright (C) 2004 - 2014 Tony Scaminaci (Macintosh ports)
 * Licensed under the terms of the GNU General Public License version 2 (only).
 * See the file COPYING for details.
 *
 */

#define __version__ "4.23"
#define EXIT_FAIL_NONSTARTER    0x01
#define EXIT_FAIL_ADDRESSLINES  0x02
#define EXIT_FAIL_OTHERTEST     0x04

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

// MacOS X includes (Tony Scaminaci 8/2004)
// Updated 6/2014 for shared_region.h

#include <sys/sysctl.h>
#include <sys/file.h>
#include <mach/mach.h>
#include <mach/bootstrap.h>
#include <mach/host_info.h>
#include <mach/mach_error.h>
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <mach/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/shared_region.h>

#include "memtest.h"

// #include <IOKit/IOTypes.h>
// #include <IOKit/IOKitLib.h>

// MacOS X global variables

FILE		*logfile = NULL;
char		*temp_memory;
char		ProductName[16] = "\0";
char		ProductVersion[16] = "\0";
char		BuildVersion[16] = "\0";

// MacOS X function prototypes

unsigned long long GetFreeMem(void);

struct test tests[] = {
	{ "Random Value", test_random_value },
	{ "Compare XOR", test_xor_comparison },
	{ "Compare SUB", test_sub_comparison },
	{ "Compare MUL", test_mul_comparison },
	{ "Compare DIV",test_div_comparison },
	{ "Compare OR", test_or_comparison },
	{ "Compare AND", test_and_comparison },
	{ "Sequential Increment", test_seqinc_comparison },
	{ "Solid Bits", test_solidbits_comparison },
	{ "Block Sequential", test_blockseq_comparison },
	{ "Checkerboard", test_checkerboard_comparison },
	{ "Bit Spread", test_bitspread_comparison },
	{ "Bit Flip", test_bitflip_comparison },
	{ "Walking Ones", test_walkbits1_comparison },
	{ "Walking Zeroes", test_walkbits0_comparison },
	{ NULL, NULL }
};

void check_posix_system(void)
  {
    if (sysconf(_SC_VERSION) < 198808L)
	  {
        fprintf(stderr, "WARNING: POSIX version is older than 199908.\n");
        fprintf(stderr, "_SC_VERSION is %lu\n", sysconf(_SC_VERSION));
		if (logfile != NULL)
		  {
			fprintf(logfile, "WARNING: POSIX version is older than 199908.\n");
			fprintf(logfile, "_SC_VERSION is %lu\n", sysconf(_SC_VERSION));
		  }
      }
  }
 
void Get_Macosx_Info(void)
  {
	FILE			*fileptr = NULL;
	char			linedata[128];
	char			colonfound = 0;
	char			stringvalid = 0;
	char			linecount = 0;
	unsigned int	i;
	
	if ((fileptr = popen("/usr/bin/sw_vers", "r")) != NULL)
	  {
		while (fgets(linedata, 128, fileptr) != NULL)
		  {
			for (i=0; i < strlen(linedata); i++)
			  {
				if (!colonfound && (linedata[i] == ':'))
				  {
					colonfound = 1;
					linecount += 1;
					continue;
				  }
				if (colonfound && (linedata[i] != ' ') && !stringvalid)
				  {
					stringvalid = 1;
					continue;
				  }
				if (stringvalid)
				  {
					if (linecount == 1)
					  strncpy(ProductName, &linedata[i], strlen(linedata) - i - 1);
					else if (linecount == 2)
					  strncpy(ProductVersion, &linedata[i], strlen(linedata) - i - 1);
					else if (linecount == 3)
					  strncpy(BuildVersion, &linedata[i], strlen(linedata) - i - 1);
					stringvalid = 0;
					colonfound = 0;
					break;
				  }
			  }
		  }
		fclose(fileptr);
	  }
  }

// For MacOS X, get amount of free physical RAM at the instant GetFreeMem is called
// Modified function/variable lengths to unsigned long long (64-bit) as required
// to support installed memory sizes > 4 GB. Added by Tony Scaminaci 5/13/2005 

unsigned long long GetFreeMem()
{
  vm_statistics_data_t		vm_stat;
  mach_port_t				host_priv_port;
  mach_msg_type_number_t	host_count;
  kern_return_t				kern_error;
  unsigned long long		FreeMem;		// Free real (physical) memory

// Get total system-wide memory usage structure

  host_priv_port = mach_host_self();	// Get host machine information
  host_count = sizeof(vm_stat)/sizeof(integer_t);
  kern_error = host_statistics(host_priv_port, HOST_VM_INFO, (host_info_t)&vm_stat, &host_count);
  if (kern_error != KERN_SUCCESS)
	{
	  mach_error("host_info", kern_error);
	  exit(EXIT_FAILURE);
	}
  FreeMem = ((unsigned long long) vm_stat.free_count) * vm_page_size;	// Calculate total free memory in bytes
  FreeMem &= 0xFFFFFFFFFFFFFFC0ull;						// Align byte count to 64-byte boundary
  return(FreeMem);
}

// Check current user level. For OS versions earlier than 10.5, use the sysctl selector to determine
// if we're in single or multiuser mode. For 10.5 and beyond, use sysctlbyname as noted below.
// Changed from sysctl to sysctlbyname on 4/18/08 per Terry Lambert's recommendation.
// Check the kern.singleuser system parameter. If it's 0, we're in multi-user mode, else
// we're in single-user mode. Invert the returned result for backwards compatibility.

int	get_user_level()
  {
	int		Selectors[2] = {CTL_KERN, KERN_SECURELVL};
	int		UserMode;
	size_t	Length = sizeof(UserMode);

	if (sysctlbyname("kern.singleuser", &UserMode, &Length, NULL,  (size_t) 0) == -1)
	  {
		sysctl(Selectors, 2, &UserMode, &Length, NULL, (size_t) 0);
		return UserMode;
	  }
	return (!UserMode);
  }
  
void store_dimm_data(char data)
  {
	int	index = 0;
	
	printf("Character: %c", data);
	temp_memory[index++] = data;  
  }

void disableMallocDebug(char *const argv[])
  {
    if (getenv("MallocLogFile") == NULL)
	  {
		if (putenv("MallocLogFile=/dev/null") == -1)
		  {
			perror("ERROR: putenv");
			exit(1);
		  }
		if (execvp(argv[0], argv) == -1)
		  {
			perror("ERROR: execvp");
			exit(1);
		  }
	  }
  }
  
// Get CPU information
  
int Get_CPUInfo(void)
 {
	int		hasAltiVec = 0, hasSSE3 = 0, NoOfCPUs = 0, ByteOrder = 0;
	int		CPUType = 0;	// Initialize to Intel CPU
	size_t	Length = sizeof(int);
	
	sysctlbyname("hw.ncpu", &NoOfCPUs, &Length, NULL, (size_t) 0);
	sysctlbyname("hw.byteorder", &ByteOrder, &Length, NULL, (size_t) 0);
	if (ByteOrder == 4321)	// 4321 = Big Endian --> CPU is PPC
	  {
		CPUType = 1;	// CPU is PowerPC
		sysctlbyname("hw.optional.altivec", &hasAltiVec, &Length, NULL, (size_t) 0);
		return (hasAltiVec + (NoOfCPUs << 8) + (CPUType << 16));
	  }
	else				// 1234 = Little Endian --> CPU is Intel
	  {
		sysctlbyname("hw.optional.sse3", &hasSSE3, &Length, NULL, (size_t) 0);
		return (hasSSE3 + (NoOfCPUs << 8) + (CPUType << 16));
	  }
 }

// Intelligent command-line parser. Not infallible but pretty good.
// Added by Tony Scaminaci 10/2006
// Added help switch -h, 11/2014

int parse_args(int argc, char *const argv[])
  {
	int i;
	int arg_mask, args_remaining;
	int log_flag, size_flag, loop_flag, quick_flag;
	unsigned int loop_count;
	ul memsize_mb;
	
	arg_mask = log_flag = size_flag = loop_flag = memsize_mb = quick_flag = 0;
	loop_count = 1;
	
	if (argc == 1)						// Memtest invoked without arguments 
	  {
		arg_mask |= (1 << 4);			// Default number of passes to 1
		return (arg_mask);				// No parsing necessary
	  }
	  
	args_remaining = argc - 1;			// Don't count memtest command itself
	
	// Command line arguments exist so scan all arguments and set the appropriate
	// arg_mask bits and flags.
	
	for (i = 1; i < argc; i++)
	{
      if (!strcmp (argv[i], "-h"))
      {
        fprintf(stdout, "Usage: memtest <arg1> <arg2> <arg3> <arg4>\n\n");
        fprintf(stdout, "<arg1>: The amount of memory to be tested in megabytes. If arg1 is omitted, the default\n        value is assumed to be 'all' which tests all available free memory. Valid values\n        for arg1 are 'all' (without the quotes) or an integer specifying the number of\n        megabytes to test. If this number exceeds the currently available amount of free\n        memory, the value will default to 'all'. Note that if arg1 is omitted and arg2 or\n        arg3 is numeric, it will be interpreted as the number of megabytes to be tested.\n        The first numeric argument encountered will be interpreted as the number of megabytes\n        to be tested unless 'all' (without the quotes) has been specified in some position.\n        If specified, the 'all' argument may appear in any position on the command line.\n\n");
        fprintf(stdout, "<arg2>: Number of test passes to run. If arg2 is omitted, the default value is assumed to\n        be 1 and a single pass of the test suite will be run. Up to 255 passes may be run.\n\n");
        fprintf(stdout, "<arg3>: Specifies whether a transcript of test results will be written to a logfile named\n        'memtest.log' in the current working directory. If arg3 is omitted, file logging\n        is disabled. Valid values for arg3 are -l or -L. The log file switch may be placed\n        anywhere on the command line.\n\n");
        fprintf(stdout, "<arg4>: Specifies whether memtest should run a faster but abbreviated set of tests using\n        the 'quick' (without the quotes) keyword. The 'quick' specifier may be placed\n        anywhere on the command line.\n\n");
        fprintf(stdout, "An intelligent command-line parser reduces the importance of the order of arguments. For\nexample, the 'all', '-l', and 'quick' options may be entered in any order with respect to\neach other or the numerical command line arguments. Note that when numerical arguments are\nspecified, memtest will interpret the first number as the amount of memory to be tested\nand the second number as the number of test passes to run.\n\n");
        fprintf(stdout, "Example: /Applications/memtest/memtest -l 5000 4 (Test 5000 MB of memory, run 4 passes,\n                                                  and save results to a log file)\n\n");
        fprintf(stdout, "*****  Summary of Available Command Line Switches  *****\n");
        fprintf(stdout, "-h    : Print this listing\n");
        fprintf(stdout, "all   : Test all available memory in a single processor thread, position independent switch\n");
        fprintf(stdout, "quick : Run an abbreviated set of tests, faster testing, position independent switch\n");
        fprintf(stdout, "-l,-L : Write results to a log file on disk, position independent switch\n\n");
        exit(EXIT_SUCCESS);
      }
	  else if (!log_flag && (!strcmp (argv[i], "-l") || !strcmp (argv[i], "-L")))
	  {
		arg_mask |= USE_LOG_FILE;
		log_flag = 1;
		args_remaining--;
	  }
	  else if (!size_flag && (!strcmp(argv[i], "all") || !strcmp(argv[i], "ALL")))
	  {
		arg_mask |= TEST_SIZE_MB;		// Set all bits in memory size field
		size_flag = 1;
		args_remaining--;
	  }
	  else if (!quick_flag && (!strcmp(argv[i], "quick") || !strcmp(argv[i], "QUICK")))
	  {
		arg_mask |= QUICK_FLAG;			// Quick test option chosen
		quick_flag = 1;
		args_remaining--;
	  }
	  else if (!strcmp(argv[i], "0"))
	  {
		fprintf(stderr, "ERROR: Invalid argument '0' found on command line.\n\n");
		exit(EXIT_FAIL_NONSTARTER);
	  }
	  else if (!size_flag)
	  {
	    if ((memsize_mb = (unsigned long) strtoul(argv[i], NULL, 0)) <= 0xFFFFF) 
		  {
			arg_mask |= (memsize_mb << 12);		// Set memory size field to requested amount
			size_flag = 1;
			args_remaining--;
		  }
		else
		  {
			fprintf(stderr, "ERROR: Invalid memory test size, max is 1048575 MB.\n\n");
			exit(EXIT_FAIL_NONSTARTER);
		  }
	   }
	  else if (size_flag && args_remaining)			// If present, the second numeric argument
	  {												// must be a valid number of test passes
	    if ((loop_count = (unsigned int) strtoul(argv[i], NULL, 0)) < 256) 
		  {
			loop_flag = 1;
			args_remaining--;
			if (loop_count)
			  arg_mask |= (loop_count << 4);		// Set number of passes to requested amount
			else
			  arg_mask |= (1 << 4);					// Default number of passes to 1
		  }
		else
		  {
			fprintf(stderr, "ERROR: Invalid number of test passes, max is 255.\n\n");
			exit(EXIT_FAIL_NONSTARTER);
		  }
	   }
	 if (!args_remaining)							// If all else fails...
	   {
		 if (!loop_flag)
		   {
			 arg_mask |= (loop_count << 4);			// Default number of passes to 1
			 loop_flag = 1;
		   }
		 if (!size_flag)
		   {
			 arg_mask |= TEST_SIZE_MB;				// Default to test all memory
			 size_flag = 1;
		   }
	   }
//	  printf("argv[i] = %s\n", argv[i]);
//	  printf("loop_flag = %d\n", loop_flag);
//	  printf("loop_count = %d\n", loop_count);
//	  printf("args_remaining = %d\n\n", args_remaining);
	}
	return (arg_mask);
  }

int main(int argc, char *const argv[]) {
    int loop, i;
	int loops;
    size_t halflen, count, bufsize;
    ptrdiff_t pagesizemask;
    void volatile *buf, *aligned;
    ulv *bufa, *bufb;
    int do_mlock = 0, done_mem = 0;
	int exit_code = 0;
	int	NoArgFlag = 0;					// Set if no arguments are passed to application
	unsigned long MBAvail;				// Physical memory available for testing (MB)
	unsigned long wantmb;				// Physical memory requested for lock (MB)
	unsigned long long MemAvail;		// Physical memory available for testing (bytes)
	unsigned long long wantbytes;		// Physical memory requested for lock (bytes)
	unsigned long long wantbytes_orig;	// Copy of physical memory requested for lock (bytes)
	unsigned long long testbytes;		// Test size for single-user mode
	int	user_level;						// Single-user or multiuser mode
	int CPUInfo;						// CPU and optional vector accelerator information
	int arg_list;						// Masked list of command line arguments
	time_t StartTime, EndTime;			// Start time is in seconds since Epoch
	time_t ExecutionTime;				// Total execution time of all tests in seconds
	char work_dir[MAXPATHLEN];			// Character array holding the current working directory
//	int errcode;

//	Disable debugging messages from the malloc library. These are generated whenever malloc
//	cannot allocate the buffer size as requested. As the requests are repeatedly reduced by
//	one page size, the warnings will normally scroll continuously on the screen. Instead,
//	route them to /dev/null.

    disableMallocDebug(argv);

//  IOKit test code
//	io_service_t	device;
//	io_name_t		devName;
//	io_string_t		pathName;

//	IORegistryEntryGetName(device, devName);
//	printf("DeviceÕs name = %s\n", devName);
//	IORegistryEntryGetPath(device, kIOServicePlane, pathName);
//	printf(ÒDeviceÕs path in IOService plane = %s\nÓ, pathName);
//	IORegistryEntryGetPath(device, kIOUSBPlane, pathName);
//	printf(ÒDeviceÕs path in IOUSB plane = %s\nÓ, pathName);
//  End of IOKit test code

//	temp_memory = malloc(1024);
//	system("ioreg -p IODeviceTree -l | grep memory@0 -A 11");
//	free(temp_memory);

    printf("\nMemtest version " __version__ " (%lu-bit)\n", sizeof(size_t) << 3);
//	printf("Maximum value of unsigned long: %lu\n", ULONG_MAX);
//	printf("Size of size_t = %zd\n", sizeof(size_t));
    printf("Copyright (C) 2004 Charles Cazabon\n");
	printf("Copyright (C) 2004-2014 Tony Scaminaci (Macintosh port)\n");
    printf("Licensed under the GNU General Public License version 2 only\n\n");
	arg_list = parse_args(argc, argv);
	if (argc == 1)
	  {
		NoArgFlag = 1;
		printf("NOTE: No command-line arguments have been specified\n");
		printf("Using defaults: Test all available memory, one test pass, no logfile\n\n");
	  }
	user_level = get_user_level();
	if (arg_list & USE_LOG_FILE)
	  {
		if (!user_level)									// If we're in single-user mode,
		  system("/sbin/mount -uw /");						// make / file system writable
		if (getcwd(work_dir, (size_t)MAXPATHLEN) == NULL)	// Get current working directory
		  printf("ERROR: Working directory unavailable, no log file will be written\n\n");
		else if ((logfile = fopen ("memtest.log", "w")) == NULL)	
		  printf("ERROR: Can't open 'memtest.log', no log file will be written\n\n");
		else
		  printf("NOTE: Writing log file to %s/memtest.log\n\n", work_dir);
	  }
	if (logfile != NULL)
	  {
		fprintf(logfile, "\nMemtest version " __version__ " (%lu-bit)\n", sizeof(size_t) << 3);
		fprintf(logfile, "Copyright (C) 2004 Charles Cazabon\n");
		fprintf(logfile, "Copyright (C) 2004-2014 Tony Scaminaci (Macintosh port)\n");
		fprintf(logfile, "Licensed under the GNU General Public License version 2 only\n\n");
		fprintf(logfile, "Log file written to %s/memtest.log\n\n", work_dir);
	  }
	Get_Macosx_Info();
	if (!user_level)
	  printf("%s %s (Build %s) running in single user mode\n", ProductName, ProductVersion, BuildVersion);
	else
	  printf("%s %s (Build %s) running in multiuser mode\n", ProductName, ProductVersion, BuildVersion);
	if (logfile != NULL)
	  {
		if (!user_level)
		  fprintf(logfile, "%s %s (Build %s) running in single user mode\n", ProductName, ProductVersion, BuildVersion);
		else
		  fprintf(logfile, "%s %s (Build %s) running in multiuser mode\n", ProductName, ProductVersion, BuildVersion);
	  }
	check_posix_system();
	printf("Memory Page Size is %lu bytes\n", (unsigned long) vm_page_size);
	if (logfile != NULL)
	  fprintf(logfile, "Memory Page Size is %lu bytes\n", (unsigned long) vm_page_size);
    pagesizemask = (ptrdiff_t) ~(vm_page_size - 1);
//	printf("Pagesizemask is 0x%tx\n", pagesizemask);
	CPUInfo = Get_CPUInfo();
	if ((CPUInfo >> 16) & 0x00FF)	// Check for PPC CPU
	  {
		if (CPUInfo & 0x00FF)		// Check for Altivec unit
		  {
			printf("System has %d PPC processors(s) with Altivec\n", ((CPUInfo >> 8) & 0x00FF));
			if (logfile != NULL)
			  {
				fprintf(logfile, "System has %d PPC processors(s) with Altivec\n", ((CPUInfo >> 8) & 0x00FF));
			  }
		  }
		else
		  {
			printf("System has %d PPC processor(s), no Altivec\n", ((CPUInfo >> 8) & 0x00FF));
			if (logfile != NULL)
			  {
				fprintf(logfile, "System has %d PPC processor(s), no Altivec\n", ((CPUInfo >> 8) & 0x00FF));
			  }
		  }
	  }
	else							// CPU is Intel
	  {
		if (CPUInfo & 0x00FF)		// Check for SSE unit
		  {
			printf("System has %d Intel core(s) with SSE\n", ((CPUInfo >> 8) & 0x00FF));
			if (logfile != NULL)
			  {
				fprintf(logfile, "System has %d Intel core(s) with SSE\n", ((CPUInfo >> 8) & 0x00FF));
			  }
		  }
		else
		  {
			printf("System has %d Intel core(s), no SSE\n", ((CPUInfo >> 8) & 0x00FF));
			if (logfile != NULL)
			  {
				fprintf(logfile, "System has %d Intel core(s), no SSE\n", ((CPUInfo >> 8) & 0x00FF));
			  }
		  }
	  }
	MemAvail = GetFreeMem();			// Get 64-bit length of free memory in bytes
	MBAvail = (unsigned long)(MemAvail >> 20);			// Calculate free memory in megabytes
	if (NoArgFlag || (((unsigned int)arg_list & TEST_SIZE_MB) == TEST_SIZE_MB))
	  {
	    wantmb = MBAvail;						// "all" option specified so set requested
		wantbytes_orig = wantbytes = MemAvail;	// memory size equal to available memory
	  }
	else								// Else, set requested memory size to user's request
	  {
		wantmb = ((unsigned int)arg_list & TEST_SIZE_MB) >> 12;
		wantbytes_orig = wantbytes = (unsigned long long) (wantmb << 20);
	  }
//	printf("Free memory: %llu MB (%llu bytes)\n", (ull) MBAvail, (ull) MemAvail);
//	printf("Requested memory: %llu MB (%llu bytes)\n", (ull) wantmb, (ull) wantbytes);
	printf("Total free memory is %llu MB\n", (ull) MBAvail);
	printf("Requested test memory is %llu MB\n", (ull) wantmb);
	if (logfile != NULL)
	  {
//		fprintf(logfile, "Free memory: %llu MB (%llu bytes)\n", (ull) MBAvail, (ull) MemAvail);
//		fprintf(logfile, "Requested memory: %llu MB (%llu bytes)\n", (ull) wantmb, (ull) wantbytes);
		fprintf(logfile, "Total free memory is %llu MB\n", (ull) MBAvail);
		fprintf(logfile, "Requested test memory is %llu MB\n", (ull) wantmb);
	  }
    if (wantbytes < (unsigned long long) vm_page_size)
	  {
        fprintf(stderr, "\nERROR: Memory test size must be greater than 0 or 'all'.\n\n");
	        exit(EXIT_FAIL_NONSTARTER);
      }
	if (user_level && wantbytes > MemAvail)			// Limit memory allocation in multiuser modes
	  {
		printf("NOTE: Reducing test size for Darwin kernel stability...\n");
		if (logfile != NULL)
		  fprintf(logfile, "NOTE: Reducing test size for Darwin kernel stability...\n");
		wantbytes = MemAvail;						// Guarantee that no paging will occur
	  }
//	In single-user mode, reduce the allocation request by a preset factor and align to 64-byte boundary
//  as a first attempt.
	testbytes = (((unsigned long long) (MemAvail * 0.982)) >> 6) << 6;
	if (!user_level && wantbytes > testbytes)		// Further limit memory allocation in single-user mode
	  {
		printf("NOTE: Reducing test size for Darwin kernel stability...\n");
		if (logfile != NULL)
		  fprintf(logfile, "NOTE: Reducing test size for Darwin kernel stability...\n");
		wantbytes = testbytes;						// Prevent the Darwin kernel from becoming unresponsive
	  }
//	Finally, limit the allocation request size to the maximum memory that the platform (32 or 64-bit) can address
	if (wantbytes > ULONG_MAX)
	  wantbytes = ULONG_MAX;
//  Set the number of test loops
	loops = (arg_list & NUMBER_OF_PASSES) >> 4;	// 0 <= loops <= 255 (0 = continuous looping, default)
    buf = NULL;									// Initialize memory test buffer pointer
    while (!done_mem)
	  {
        while (!buf && wantbytes)			// Attempt to allocate requested number of bytes
		  {
            buf = (void volatile *) malloc((size_t) wantbytes);
            if (!buf)						// If allocation request fails, reduce requested
			  wantbytes -= vm_page_size;	// allocation by one page and try again
          }
        bufsize = (size_t) wantbytes;
        if ((size_t) buf % vm_page_size)	// If buffer is not aligned to a memory page boundary
		  {
            printf("Aligning test buffer to nearest page boundary...\n");
			if (logfile != NULL)
			  fprintf(logfile, "Aligning test buffer to nearest page boundary...\n");
			fflush(stdout);
            aligned = (void volatile *) ((size_t) buf & (ul)pagesizemask);
            bufsize -= ((size_t) aligned - (size_t) buf);
          }
		else
		  aligned = buf;				// Test buffer was already aligned to a page boundary
		if (sizeof(size_t) == 8)
		  printf("Allocated test memory is %llu MB at local address 0x%016llx\n", (ull) bufsize >> 20, (ull) aligned);
		else
		   printf("Allocated test memory is %lluMB at local address 0x%08lx\n", (ull) bufsize >> 20, (ul) aligned);
		if (logfile != NULL)
		  {
			if (sizeof(size_t) == 8)
			  fprintf(logfile, "Allocated test memory is %lluMB at local address 0x%016llx\n", (ull) bufsize >> 20, (ull) aligned);
			else
			  fprintf(logfile, "Allocated test memory is %lluMB at local address 0x%08lx\n", (ull) bufsize >> 20, (ul) aligned);
		  }
//	The buffer is now aligned to a memory page boundary so attempt to lock the memory for exclusive use
		printf("Attempting memory lock... ");
		if (logfile != NULL)
		  fprintf(logfile, "Attempting memory lock... ");
		fflush(stdout);
        if (mlock((void *) aligned, bufsize) != 0)
		  {
            switch(errno)
			  {
				case EAGAIN:
					printf("WARNING: Memory lock failed - running unlocked...\n\n");
					if (logfile != NULL)
					  fprintf(logfile, "WARNING: Memory lock failed - running unlocked...\n\n");
//					free((void *) buf);
//					buf = NULL;
					do_mlock = 0;
					done_mem = 1;									
//					wantbytes = wantbytes - (1000 *vm_page_size);	// Reduce next request by 1000 pages
//					wantbytes = wantbytes_orig;
//					wantbytes = 4294967296;
					break;					  
				case EINVAL:
					printf("WARNING: Memory lock failed due to non-aligned page address - running unlocked...\n\n");
					if (logfile != NULL)
					  fprintf(logfile, "WARNING: Memory lock failed due to non-naligned page address - running unlocked...\n\n");
					do_mlock = 0;
					done_mem = 1;
					break;
                case ENOMEM:
                    printf("WARNING: Too many pages requested - reducing and trying again...\n\n");
					if (logfile != NULL)
					  fprintf(logfile, "WARNING: Too many pages requested - reducing and trying again...\n\n");
					do_mlock = 0;
					done_mem = 1;
//                  free((void *) buf);
//                  buf = NULL;
//                  wantbytes -= vm_page_size;
                    break;
                case EPERM:
                    printf("WARNING: Insufficient permissions - running unlocked...\n\n");
					if (logfile != NULL)
					  fprintf(logfile, "WARNING: Insufficient permissions - running unlocked...\n\n");
                    do_mlock = 0;
					done_mem = 1;
//					free((void *) buf);
//					buf = NULL;
//					wantbytes = wantbytes_orig;
                    break;
                default:
                    printf("WARNING: Memory lock failed for unknown reason - running unlocked...\n\n");
					if (logfile != NULL)
					  fprintf(logfile, "WARNING: Memory lock failed for unknown reason - running unlocked...\n\n");
                    do_mlock = 0;
                    done_mem = 1;
             }
		  }
		else
		  {
            printf("locked successfully\n");
			if (logfile != NULL)
			  fprintf(logfile, "locked successfully\n");
			fflush(stdout);
			do_mlock = 1;
            done_mem = 1;
          }
    }

    if (!do_mlock)
	  {
		fprintf(stderr, "NOTE: Testing with unlocked memory\n\n");
		if (logfile != NULL)
		  fprintf(logfile, "NOTE: Testing with unlocked memory\n\n");
	  }

    halflen = bufsize / 2;
    count = halflen / sizeof(ul);
    bufa = (ulv *) aligned;
    bufb = (ulv *) ((size_t) aligned + halflen);
	printf("Partitioning memory into 2 comparison buffers...\n");
	if (sizeof(size_t) == 8)
	  {
		printf("Buffer A: %llu MB starts at local address 0x%016llx\n", (ull) halflen >> 20, (ull) bufa);
		printf("Buffer B: %llu MB starts at local address 0x%016llx\n\n", (ull) halflen >> 20, (ull) bufb);
	  }
	else
	  {
		printf("Buffer A: %llu MB starts at local address 0x%08lx\n", (ull) halflen >> 20, (ul) bufa);
		printf("Buffer B: %llu MB starts at local address 0x%08lx\n\n", (ull) halflen >> 20, (ul) bufb);
	  }	
	fflush(stdout);
	if (logfile != NULL)
	  {
	  	fprintf(logfile, "Splitting allocated memory into 2 comparison buffers...\n");
		if (sizeof(size_t) == 8)
		  {
			fprintf(logfile, "Buffer A: %llu MB starts at local address 0x%016llx\n", (ull) halflen >> 20, (ull) bufa);
			fprintf(logfile, "Buffer B: %llu MB starts at local address 0x%016llx\n\n", (ull) halflen >> 20, (ull) bufb);
		  }
		else
		  {
			fprintf(logfile, "Buffer A: %llu MB starts at local address 0x%08lx\n", (ull) halflen >> 20, (ul) bufa);
			fprintf(logfile, "Buffer B: %llu MB starts at local address 0x%08lx\n\n", (ull) halflen >> 20, (ul) bufb);
		  }
		fflush(logfile);
	  }
	if (!loops)
	  {
		printf("NOTE: Test sequences will run continuously until terminated by Ctrl-C...\n\n");
		if (logfile != NULL)
		  fprintf(logfile, "NOTE: Test sequences will run continuously until terminated by Ctrl-C...\n\n");
	  }
	else
	  {
		if (loops == 1)
		  {
			printf("Running 1 test sequence... (CTRL-C to quit)\n\n");
			if (logfile != NULL)
			  fprintf(logfile, "Running 1 test sequence... (CTRL-C to quit)\n\n");
		  }
		else
		  {
			printf("Running %d test sequences... (CTRL-C to quit)\n\n", loops);
			if (logfile != NULL)
			  fprintf(logfile, "Running %d test sequences... (CTRL-C to quit)\n\n", loops);
		  }
	  }
	time(&StartTime);	// Get current time (time at which tests begin)
    for(loop = 1; ((!loops) ||  loop <= loops); loop++) {
        printf("Test sequence %d", loop);
		if (logfile != NULL)
		  fprintf(logfile, "Test sequence %d", loop);
        if (loops) {
            printf(" of %d", loops);
			if (logfile != NULL)
			  fprintf(logfile, " of %d", loops);
        }
        printf(":\n\n");
		printf("Running tests on full %llu MB region...\n", (ull) bufsize >> 20);
    	printf("  %-20s:    ", "Stuck Address");
		fflush(stdout);
		if (logfile != NULL)
		  {
			fprintf(logfile, ":\n\n");
		    fprintf(logfile, "Running tests on entire %llu MB region...\n", (ull) bufsize >> 20);
			fprintf(logfile, "  %-20s:    ", "Stuck Address");
			fflush(logfile);
		  }
    	if (!test_stuck_address(aligned, arg_list, bufsize / sizeof(ul)))
		  {
			printf("ok\n");
			if (logfile != NULL)
			  {
				fprintf(logfile, "ok\n");
				fflush(logfile);
			  }
		  }
		else
		  exit_code |= EXIT_FAIL_ADDRESSLINES;
		printf("  %-20s:    ", "Linear PRN");
		fflush(stdout);
		if (logfile != NULL)
		  {
			fprintf(logfile, "  %-20s:    ", "Linear PRN");
			fflush(logfile);
		  }
    	if (!test_linear_prn(aligned, arg_list, bufsize / sizeof(ul), StartTime))
		  {
			printf("ok\n");
			if (logfile != NULL)
			  {
				fprintf(logfile, "ok\n");
				fflush(logfile);
			  }
		  }
		else
		  exit_code |= EXIT_FAIL_OTHERTEST;
		printf("Running comparison tests using %lluMB buffers...\n", (ull) halflen >> 20);
		if (logfile != NULL)
		  fprintf(logfile, "Running comparison tests using %lluMB buffers...\n", (ull) halflen >> 20);
    	for (i = 0; ; i++)
		  {
/*		  	if (arg_list & QUICK_FLAG)				// Check for quick test run
			  {
				if (i == 0)
				  continue;							// Skip test 0 for quick run
			  } */
			if (!tests[i].name) break;
			  printf("  %-20s:    ", tests[i].name);
			if (logfile != NULL)
			  fprintf(logfile, "  %-20s:    ", tests[i].name);
			if (!tests[i].fp(bufa, bufb, arg_list, count))
			  {
				printf("ok\n");
				if (logfile != NULL)
				fprintf(logfile, "ok\n");
			  }
			else
			  exit_code |= EXIT_FAIL_OTHERTEST;
			fflush(stdout);
			if (logfile != NULL)
			  fflush(logfile);
		  }
    	printf("\n");
		fflush(stdout);
		if (logfile != NULL)
		  {
			fprintf(logfile, "\n");
			fflush(logfile);
		  }
    }
    if (do_mlock) munlock((void *) aligned, bufsize);
	time(&EndTime);							// Get current time (time at which tests end)
	ExecutionTime = EndTime - StartTime;	// Calculate total run time of all tests
	if (!exit_code)
	  {
		printf("All tests passed!  Execution time: %lu seconds.\n\n", ExecutionTime);
		if (logfile != NULL)
		  {
			fprintf(logfile, "All tests passed!  Execution time: %lu seconds.\n\n", ExecutionTime);
			fclose(logfile);
		  }
	  }
	else
	  {
		if (exit_code & EXIT_FAIL_ADDRESSLINES)
		  {
			printf("*** Address Test Failed ***  One or more DIMM address lines are non-functional.\n");
			printf("Execution time: %lu seconds.\n\n", ExecutionTime);
			if (logfile != NULL)
			  {
				fprintf(logfile, "*** Address Test Failed ***  One or more DIMM address lines are non-functional.\n");
				fprintf(logfile, "Execution time: %lu seconds.\n\n", ExecutionTime);
				fclose(logfile);
			  }
		  }
		else if (exit_code & EXIT_FAIL_OTHERTEST)
		  {
			printf("*** Memory Test Failed ***  Please check transcript for details.\n");
			printf("Execution time: %lu seconds.\n\n", ExecutionTime);
			if (logfile != NULL)
			  {
				fprintf(logfile, "*** Memory Test Failed ***  Please check logfile for details.\n");
				fprintf(logfile, "Execution time: %lu seconds.\n\n", ExecutionTime);
				fclose(logfile);
			  }
		  }
	  }
	fflush(stdout);
//	if (!user_level)					// If we're in single-user mode,
//	  system("/sbin/mount -urf /");		// return file system to read-only
    exit(0);
}
