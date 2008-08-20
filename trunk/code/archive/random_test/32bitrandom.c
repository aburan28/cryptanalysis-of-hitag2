#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define u8			unsigned char
#define u32			unsigned int
#define u64			unsigned long long
#define s32			signed int

u64 get_random_plain()
{
	return rand(); 
}

u64 get_random_1(u32 bits)
{
	u32 i = 0;
	u64 random_number = 0;
	u64 rand_out = 0;

	for(i = 0; i < bits - 16; i++)
	{
		rand_out = rand();
		random_number = (random_number << 1) ^ rand_out ^ (rand_out >> 1);
	}

	return random_number;
}

u64 get_random_2(u32 bits)
{
	u32 i = 0;
	u64 random_number = 0;
	u64 rand_out = 0;

	for(i = 0; i < bits - 16; i++)
	{
		rand_out = rand();
		random_number = (random_number << 1) ^ rand_out;
	}

	return random_number;
}

int main(void)
{
	time_t seconds;
	u64 runtime = 0;
	u64 i = 0;
	u64 first_random = 0;

	u64 random = 0;

	time(&seconds);
	srand(seconds);

	runtime = pow(2,32);
	
	//first_random = get_random_plain();
	first_random = get_random_1(32);
	//first_random = get_random_2(32);
	
	printf("\nFirst random number: %llx", first_random);

	for(i = 0; i < runtime; i++)
	{
		//random = get_random_plain();	
		random = get_random_1(32);	
		//random = get_random_2(32);	
		
		if(random == first_random)
		{
			printf("\n\n Repetition of random number! Period: %llu\n", i);
			break;
		}
	}
}			
