#include<stdio.h>
#include <math.h>		/* for power function */
#include <time.h>
#include <stdlib.h>

#include "common.h"		/* for common definitions */
#include "hitag2.h"		/* for hitag2 function prototypes */
#include "attack_helper.h"	/* for helper function prototypes */

u64 get_random(u32 bits)
{
	u32 i = 0;
	u64 random_number = 0;
	u64 rand_out = 0;

	for(i = 0; i < bits - 16; i++)
	{
		rand_out = rand();
		random_number = random_number ^ (random_number << 1) ^ (random_number << 2) ^ rand_out;
	}

	return random_number;
}

// u64 get_random(u32 bits)
// {
// 	u32 i = 0;
// 	u64 random_number = 0;
// 	u64 rand_out = 0;
// 
// 	for(i = 0; i < bits - 16; i++)
// 	{
// 		rand_out = rand() % 65535;
// 		random_number = (random_number << 1) ^ rand_out ^ (rand_out >> 1);
// 	}
// 
// 	return random_number;
// }

void prepare_tags(u64 * c_tags)
{
	u64 state = 0;
	u64 i = 0;
	u64 iv = 0;

	time_t seconds;
	
	time(&seconds);
	
	srand(seconds);
	
	for(;i < T; i++)
	{
		
		iv = get_random(32);
		//printf("\n%llx ", iv);	
		
		state = hitag2_init(0x524BF8ED4E4FULL, 0x69574349, iv);

		*c_tags = (u64) hitag2_prefix(&state, prefix_bits); 
		//printf("\nNew Tag: %llx ", *c_tags);
		c_tags++;
		*c_tags = (u64) iv; 
		//printf(" New IV: %llx", *c_tags);
		c_tags++;
	}
	
	printf("\nTags made available ...");
}

void prepare_keystream(u64 * c_keystream)
{
	u64 state = 0;
	u64 i = 0;

	/* Randomly select a key, a IV and a Serial ID; to determine the initial state */
	state = hitag2_init (rev64 (0x52B49EA34972ULL), rev32 (0x69574349), rev32 (0x72456E65));

	for(;i < D/64 + 1; i++)
	{
		*c_keystream = (u64) hitag2_prefix(&state, 64);
		c_keystream++;
	}
	printf("\nKeystream made available ...");
}

void mapping_function(u64 * state, u32 i)
{
	u64 prefix = 0;

	/* do the function f(state) - gives prefix of that state */
	prefix = hitag2_prefix(state, prefix_bits);

	/* do the permutation function (prefix to state) */
	*state = prefix ^ ((u64) i);
}

void initialize_matrix()
{
	u64 i = 0;
	u64 j = 0;

	printf("\nInside Initialization matrix %d", N);
	for(i = 0; i < N; i++)
	{
		for(j = 0; j < N; j++)
		{
			transition_matrix[i][j] = 0;
		}
	}

	for(i = 0; i < 47; i++)
	{
		transition_matrix[i + 1][i] = 1;
	}

	/* tap bits 0,2,3,6,7,8,16,22,23,26,30,41,42,43,46,47 */

	transition_matrix[0][47 - 0] = 1;
	transition_matrix[0][47 - 2] = 1;
	transition_matrix[0][47 - 3] = 1;
	transition_matrix[0][47 - 6] = 1;
	transition_matrix[0][47 - 7] = 1;
	transition_matrix[0][47 - 8] = 1;
	transition_matrix[0][47 - 16] = 1;
	transition_matrix[0][47 - 22] = 1;
	transition_matrix[0][47 - 23] = 1;
	transition_matrix[0][47 - 26] = 1;
	transition_matrix[0][47 - 30] = 1;
	transition_matrix[0][47 - 41] = 1;
	transition_matrix[0][47 - 42] = 1;
	transition_matrix[0][47 - 43] = 1;
	transition_matrix[0][47 - 46] = 1;
	transition_matrix[0][47 - 47] = 1;

	for(i = 0; i < N; i++)
	{
		for(j = 0; j < N; j++)
		{
			transition_matrix_2n[i][j] = transition_matrix[i][j];
		}
	}

	printf("\n");
	fflush(stdout);
	for(i = 0; i < N; i++)
	{
		for(j = 0; j < N; j++)
		{
			printf("%1x", transition_matrix[i][j]);
			fflush(stdout);
		}
		printf("\n");
		fflush(stdout);
	}
	printf("\n");
	fflush(stdout);

	square_matrix_2n();

	//print the squared matrix
	for(i = 0; i < N; i++)
	{
		for(j = 0; j < N; j++)
		{
			//printf("%1x", transition_matrix_2n[i][j]);
		}
		//printf("\n");
	}
	//printf("\n");
}

/***********************************************************************************************************/
void square_matrix_2n()
{
	u64 i = 0;
	u64 j = 0;
	u64 k = 0;
	u64 count = 0;
	u32 time_order = 0;

	u8 c_temp = 0;
	u64 l_temp = 0;
	u64 l_xor = 0;
	u64 one = 1;
	u64 zero = 0;

	u64 matrix_1[N];
	u64 matrix_2[N];

	time_order = (u32) log2(T);
	// For time_index number of times, square the matrix transition_matrix_2n
	for(i = 0; i < time_order; i++)
	{
		//convert the matrix into array of u64
		for(j = 0; j < N; j++)
		{
			for(k = 0; k < N; k++)
			{
				if(transition_matrix_2n[j][k] == 1)
				{
					l_temp = ((l_temp >> (47 - k)) ^ one) << (47 - k);
				}

				else if(transition_matrix_2n[j][k] == 0)
				{
					l_temp = ((l_temp >> (47 - k)) ^ zero) << (47 - k);
				}
			}

			matrix_1[j] = l_temp;
			l_temp = 0;
		}

		//print the u64 array conversion of transition_matrix_2n
		for(j = 0; j < N; j++)
		{
			//printf("%llx ", matrix_1[j]);
		}

		//transpose of the matrix transition_matrix_2n
		for(j = 0; j < N; j++)
		{
			for(k = 0; k < N; k++)
			{
				if(j > k)
				{
					c_temp = transition_matrix_2n[j][k];
					transition_matrix_2n[j][k] = transition_matrix_2n[k][j];
					transition_matrix_2n[k][j] = c_temp;
				}
			}
		}

		//print the transpose matrix
		for(j = 0; j < N; j++)
		{
			for(k = 0; k < N; k++)
			{
				//printf("%1x", transition_matrix_2n[j][k]);
			}
			//printf("\n");
		}
		//printf("\n");

		//convert the transposed matrix into u64 array
		for(j = 0; j < N; j++)
		{
			for(k = 0; k < N; k++)
			{
				if(transition_matrix_2n[j][k] == 1)
				{
					l_temp = ((l_temp >> (47 - k)) ^ one) << (47 - k);
				}

				else if(transition_matrix_2n[j][k] == 0)
				{
					l_temp = ((l_temp >> (47 - k)) ^ zero) << (47 - k);
				}

			}

			matrix_2[j] = l_temp;
			l_temp = 0;
		}

		//print the u64 array conversion of transpose of transition_matrix_2n
		for(j = 0; j < N; j++)
		{
			//printf("%llx %llx\n", matrix_1[j], matrix_2[j]);
		}

		//perform operations on the two u64 arrays and save the resultant value in the corresponding cell of the matrix
		for(j = 0; j < N; j++)
		{
			for(k = 0; k < N; k++)
			{
				// AND of the two rows
				l_temp = matrix_1[j] & matrix_2[k];


				l_xor = zero;

				for(count = 0; count < N; count++)
				{
					l_xor = l_xor ^ (l_temp >> (count));
				}

				transition_matrix_2n[j][k] = (u8) l_xor & one;
			}
		}

		l_temp = 0;
		l_xor = 0;

	}
}


/***********************************************************************************************************/
void compute_new_state(u64 * state_ptr)
{
	u64 j, k;
	u64 l_temp = 0;
	u64 l_xor = 0;
	u64 one = 1;
	u64 zero = 0;

	u64 matrix_2[N];
	u64 state = *state_ptr;
	u64 new_state = 0;

	//convert the transition_matrix_2n matrix into u64 array
	for(j = 0; j < N; j++)
	{
		for(k = 0; k < N; k++)
		{
			if(transition_matrix_2n[j][k] == 1)
			{
				l_temp = ((l_temp >> (47 - k)) ^ one) << (47 - k);
			}

			else if(transition_matrix_2n[j][k] == 0)
			{
				l_temp = ((l_temp >> (47 - k)) ^ zero) << (47 - k);
			}

		}

		matrix_2[j] = l_temp;
		l_temp = 0;
	}

	//print transition_matrix_2n
	for(j = 0; j < N; j++)
	{
		//printf("%12llx \n", matrix_2[j]);
	}

	//printf("State: %12llx \n", state);

	for(k = 0; k < N; k++)
	{
		// AND of the two rows
		l_temp = matrix_2[k] & state;

		l_xor = zero;

		for(j = 0; j < N; j++)
		{
			l_xor = l_xor ^ (l_temp >> (j));
		}

		//printf("%x ",(l_xor & one));
		new_state = new_state + ((l_xor & one) << (47 - k));
	}

	*state_ptr = new_state;
}
