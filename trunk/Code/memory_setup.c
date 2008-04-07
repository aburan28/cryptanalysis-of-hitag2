/*
	This program is used to generate the memory data for the time-memory tradeoff attacks
	Used parameters:
	Key	= 4F 4E 4D 49 4B 52
	Serial	= 49 43 57 69
	Random	= 65 6E 45 72
*/	

#include <stdio.h>
$include "hitag2.c"

#define u8				unsigned char
#define u32				unsigned long
#define u64				unsigned __int64

/*
int (void)
{
	u32					i;
	u64					state;
	
	state = hitag2_init (rev64 (0x524B494D4E4F), rev32 (0x69574349), rev32 (0x72456E65));
	printf("Initial State: %lx\n", state);
	for (i = 0; i < 16; i++) printf ("%02X ", hitag2_byte (&state));
	printf ("\n");
	return 0;
}
*/

int memory_setup()
{
	u64 start_state = 1;		
	u64 iterations = 256;	// 268435456 = 2^28
	u64 i = 0;
	
	// open file pointer 
	
	for(i = 0; i < iterations; i++)
	{
		//call hitag function - get 48 bits prefix
		
		//save prefix and state in the file
		
		state = 	
	}
}