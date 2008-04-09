/*
	This program is used to generate the memory data for the time-memory tradeoff attacks
	Used parameters:
	Key	= 4F 4E 4D 49 4B 52
	Serial	= 49 43 57 69
	Random	= 65 6E 45 72
	
	"D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6"
*/	

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "hitag2.c"

void find_state(u64, u64 *);
void prepare_keystream(u64 *);
	
u64 memory_complexity = 65536;	// 268435456 = 2^28
u64 time_complexity = 65536;	// 1048576 = 2^20

int main()
{
	u64 c_keystream[1025];
	u64 keystream = 0;
	u64 prefix = 0;
	u64 i = 0;
	u64 state = 0;
	u32 j = 0;
	u32 counter = 0;
	
	time_t seconds;
		
	// Prepare the memory
	memory_setup_file();
	
	// Prepare longg keystream
	prepare_keystream(c_keystream);
		
	keystream = c_keystream[0];
	printf("\nKeystream: %llX %llX ... %llX %llX", c_keystream[0], c_keystream[1], c_keystream[1023], c_keystream[1024]);
	
	printf("\nStarting Attack ...");
	
	for(i = 0, j = 0; i < time_complexity; i++)
	{
		prefix = keystream >> 16;

		//printf("\nCurrent Prefix: %llX", prefix);

		find_state(prefix, &state);

		if((i % 64) == 0) j = j + 1;
		keystream = (keystream << 1) ^ ((c_keystream[j] >> (63 - (i % 64))) & 1);
		
		if(state != 0)
		{
			printf("\nMatch Found! Current State: %llx  Prefix: %llx\n", state, prefix);
			
			// Find the Initial State.
			
			// Find the Key for the Internal State
			
			exit(0);
		}
	}
	
	printf("\nNo Internal State Found");
}	

int memory_setup_file()
{
	u64 state = 0;
	u64 pre_state = 0;
			
	u64 i = 0;
	
	u64 prefix = 0;
	
	FILE *fp;
	
	// Initialize the state. This can be done also by randomly assigning a value to the state.
	
	state = hitag2_init (rev64 (0x524B494D4E4FULL), rev32 (0x69574349), rev32 (0x72456E65));
		
	fp = fopen("memory.txt","w"); 
	
	for(i = 0; i < memory_complexity; i++)
	{
		// Save the starting state
		pre_state = state;
		
		//call hitag function - get 48 bits prefix (in u64 format)
		prefix = hitag2_prefix(&state);
		
		//save prefix and state in the file
		fprintf(fp, "%12llx %12llx\n", prefix, pre_state);
	
		// **** This has to be changed to state transition function - directly go to the state after 1048576 transitions
		state = pre_state + 1048576;
	}
	fclose(fp);
	printf("\nMemory Prepared in File 'memory.txt'");
}


void find_state(u64 _prefix, u64 * _state)
{
	u64 state = 0;
	u64 i = 0;
	u64 prefix = 0;

	FILE *fp;
	
	fp = fopen("memory.txt","r"); 
	
	for(i = 0; i < memory_complexity; i++)
	{
		fscanf(fp, "%12llx %12llx\n", &prefix, &state);
		//printf("%llx %llx\n", prefix, state);
		if(prefix == _prefix)
			*_state = state;
	}
	fclose(fp);
}


void prepare_keystream(u64 * c_keystream)
{
	u64 state = 0;
	u64 i = 0;
	
	// Initial State which needs to be determined..
	state = hitag2_init (rev64 (0x524B494D4E4EULL), rev32 (0x69574349), rev32 (0x72456E65));

	for(;i < time_complexity/64 + 1; i++)
	{
		*c_keystream = (u64) hitag2_u64(&state); 
		c_keystream++;
	}
	printf("\nKeystream made available");
}








