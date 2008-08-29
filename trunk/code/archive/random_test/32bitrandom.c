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

// u64 get_random_3(u64 u32 bits)
// {
// 	u32 i = 0;
// 	u64 random_number = 0;
// 	u64 rand_out = 0;
// 
// 	for(i = 0; i < bits/16; i++)
// 	{
// 		rand_out = rand();
// 		random_number = (random_number << 16) ^ rand_out;
// 	}
// 
// 	return random_number;
// }

u64 get_random_3(u64 previous_random)
{
	u64 random_number = 0;

	previous_random = previous_random & 0xFFFFULL;
	random_number = (previous_random << 16) ^ rand();

	return random_number;
}

int main(void)
{
	time_t seconds;
	u64 runtime = 0;
	u64 i = 0;
	u64 first_random = 0;
	u64 second_random = 0;
	u64 third_random = 0;

	u64 random = 0;

	time(&seconds);
	srand(seconds);

	runtime = pow(2,32);
	
	first_random = get_random_3(first_random);
	first_random = get_random_3(first_random);
	second_random = get_random_3(first_random);
	third_random = get_random_3(second_random);
	
	printf("\nFirst random number: %llx", first_random);
	printf("\nSecond random number: %llx", second_random);
	printf("\nThird random number: %llx", third_random);
	
	for(i = 0; i < runtime; i++)
	{
		random = get_random_3(random);	
		
		if(random == first_random)
		{
			printf("\n\n Reoccurence: %llu\n", i);
			random = get_random_3(random);

			if(random == second_random)
			{
				random = get_random_3(random);
				
				if(random == third_random)
				{
					printf("\n\n Repetition of random number! Period: %llu\n", i);
					break;
				}
			}
		}
	}
}			
