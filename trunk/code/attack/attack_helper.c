/*****************************************************************************/
#include<stdio.h>
#include <math.h>		/* for power function */
#include <time.h>
#include <stdlib.h>

#include "common.h"		/* for common definitions */
#include "hitag2.h"		/* for hitag2 function prototypes */
#include "attack_helper.h"	/* for helper function prototypes */
#include "attack_dispatcher.h"

u64 get_random(u32 bits)
{
	u32 i = 0;
 	u64 random_number = 0;
 	u64 rand_out = 0;
 
 	/* output of rand() function is 16 bits on Solaris, so loop runs for (bits - 16) times 
 	 * size of random_number is finally equal to 'bits' 
 	 */
 	 
 	for(i = 0; i < bits - 16; i++)
 	{
 		rand_out = rand();
 		random_number = (random_number << 1) ^ rand_out;
 	}
 
 	return random_number;
}

void prepare_tags(u64 * c_tags)
{
	u64 state = 0;
	u64 i = 0;
	u64 iv = 0;

	time_t seconds;
	time(&seconds);
	srand(seconds);
	
	for(;i < D; i++)
	{
		iv = get_random(32);
		state = hitag2_init(secret_key, serial_id, iv);
		*c_tags = (u64) hitag2_prefix(&state, prefix_bits); 
		c_tags++;
		*c_tags = (u64) iv; 
		c_tags++;
	}
	
	printf("\nTags made available ...");
}

void prepare_keystream(u64 * c_keystream)
{
	u64 state = 0;
	u64 i = 0;

	/* Randomly select a key, a IV and a Serial ID; to determine the initial state */
	state = hitag2_init (secret_key, serial_id, init_vector);

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

	/* do the function prefix(state) - gives prefix of that state */
	prefix = hitag2_prefix(state, prefix_bits);

	/* do the reduction function R_i (prefix to state) */
	*state = prefix ^ ((u64) i);
}

void initialize_matrix()
{
	u64 i = 0;
	u64 j = 0;

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

	/* Tap bits of HiTag2: 0,2,3,6,7,8,16,22,23,26,30,41,42,43,46,47 */

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

	square_matrix_2n();
}

void square_matrix_2n()
{
	u64 i = 0;
	u64 j = 0;
	u64 k = 0;
	u64 count = 0;
	u32 square_order = 0;

	u8 c_temp = 0;
	u64 l_temp = 0;
	u64 l_xor = 0;
	u64 one = 1;
	u64 zero = 0;

	u64 matrix_1[N];
	u64 matrix_2[N];

	/* If d is the distance between two states in non-random precomputation, then d = 2^48/M (refer thesis)
	 * The number of times U is squared is log2(d), which is represented by square_order */
	square_order = (u32) (N - log2(M));

	for(i = 0; i < square_order; i++)
	{
		/* convert the matrix into array of u64 array */
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

		/* transpose of the matrix transition_matrix_2n */
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

		/* convert the transposed matrix into u64 array */
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

		/* perform operations on the two u64 arrays and save the resultant value in the corresponding cell of the new matrix */
		for(j = 0; j < N; j++)
		{
			for(k = 0; k < N; k++)
			{
				/* AND of the two rows */
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

	/* convert the transition_matrix_2n matrix into u64 array */
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

	for(k = 0; k < N; k++)
	{
		/* AND of the two rows */
		l_temp = matrix_2[k] & state;

		l_xor = zero;

		for(j = 0; j < N; j++)
		{
			l_xor = l_xor ^ (l_temp >> (j));
		}

		new_state = new_state + ((l_xor & one) << (47 - k));
	}

	*state_ptr = new_state;
}
