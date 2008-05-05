/*
	This program is used to generate the memory data for the time-memory tradeoff attacks
	Used parameters:
	Key	= 4F 4E 4D 49 4B 52
	Serial	= 49 43 57 69
	Random	= 65 6E 45 72
	
	"D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6"
*/	

#include <stdio.h>
#include "../hitag2.c"

int main()
{
	u64 current_state = 0;
	u64 initial_state = 0;
	u32 complexity = 0;
	u32 j = 0;
		
	printf("\nEnter the current state:");
	scanf("%llu", &current_state);
	printf("\nEnter the complexity:");
	scanf("%llu", &complexity);

	initial_state = current_state;
        for(j = 0; j < complexity; j++)
        	hitag2_rev_round(&initial_state);
        
        printf("\nInitial State: %llx", initial_state);
	
	
}	


