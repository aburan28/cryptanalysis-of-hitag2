#include <stdio.h>
#include <stdlib.h>
#include <string.h> 		/* for memcmp */
#include <math.h>		/* for power function */
#include "common.h"
#include "hitag2.h"		/* for common definitions */
#include "hashtable.h"		/* for hashtable */
#include <time.h>

u32 prefix_bits = 48;

u64 get_random(u32 bits)
{
	u32 i = 0;
	u64 random_number = 0;
	u64 random_bit = 0;

	for(i = 0; i < bits; i++)
	{
		random_bit = rand() % 65535;
		random_number = (random_number << 1) ^ random_bit;
	}

	return random_number;
}

void mapping_function(u64 * state, u32 i)
{
	u64 prefix = 0;

	/* do the function f(state) - gives prefix of that state */
	prefix = hitag2_prefix(state, prefix_bits);

	/* do the permutation function (prefix to state) */
	*state = prefix ^ ((u64) i);
}

int main()
{
	FILE * fp = NULL;
	u32 m = 0;
	u32 r = 0;
	u32 t = 0;
	u32 N = 48;
	
	u32 current_m = 0;
	u32 current_r = 0;
	u32 current_t = 0;
	
	u64 start_state = 0;		
	u64 end_state = 0;
	
	time_t time1, time2;
	u32 sec_diff = 0;
			
	m = pow(2, 18);
	t = pow(2, 15);
	r = pow(2, 1);
		
	fp = fopen("hellman_table.txt", "w");
	
	fprintf(fp, "%d %d %d\n", m, r, t);

	time(&time1);	
	for(current_r = 0; current_r < r; current_r++)
	{
		for(current_m = 0; current_m < m; current_m++)
		{
			/* Initialize the state, to some random value */
			start_state = get_random(N);

			/* Save the starting state */
			end_state = start_state;

			for(current_t = 0; current_t < t; current_t++)
			{
				mapping_function(&end_state, current_r + 1);
			}

			/* save start_state and end_state in the file */
			fprintf(fp, "%llu %llu\n", start_state, end_state);
		}
	}

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for preparing hashtable: %d \n", sec_diff);

	
	fclose(fp);
}

