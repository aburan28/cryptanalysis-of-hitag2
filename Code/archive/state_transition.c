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
#include <string.h> /* for memcmp */
#include <math.h>
#include "hitag2.c"

u8 transition_matrix[48][48];		/* state transition matrix A */
u8 transition_matrix_2n[48][48];	/* matrix for computing state directly after 2^n transitions */

u64 time_index = 14;
u64 memory_complexity = 65536;	// 268435456 = 2^28
u64 time_complexity = 16384;	// 1048576 = 2^20

void square_matrix_2n();		/* squares the state transition matrix n times (((A^2)^2) .. n times .. )^2 */
void compute_new_state(u64 *);		/* computes the new state from the new transition matrix by A.State */

int main()
{
	u64 i = 0;
	u64 j = 0;
	u64 state_1 = 0;
	u64 state_2 = 0;
	
	for(i = 0; i < 48; i++)
	{
		for(j = 0; j < 48; j++)
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

	for(i = 0; i < 48; i++)
	{
		for(j = 0; j < 48; j++)
		{
			transition_matrix_2n[i][j] = transition_matrix[i][j];
		}
	}

	for(i = 0; i < 48; i++)
	{
		for(j = 0; j < 48; j++)
		{
			printf("%1x", transition_matrix[i][j]);
		}
		printf("\n");
	}

	// Initialize the state.
	state_1 = state_2 = hitag2_init (rev64 (0x524B494D4E4FULL), rev32 (0x69574349), rev32 (0x72456E65));
	//state_1 = 0xcfc73b43b56aULL;
	//state_2 = 0xcfc73b43b56aULL;
	printf("\n Initial State: %llx", state_1);
	
	// Step 1: Compute transition_matrix_2n matrix
	square_matrix_2n();
	
	// Step 2: Compute new state_1 value using transition_matrix_2n matrix
	compute_new_state(&state_1);
	
	// Run hitag2_round time_complexity number of times
	for(j = 0; j < time_complexity; j++)
	{
		hitag2_next_state(&state_2);
	}

	// Check if state_1 is equal to state_2
	printf("\nState 1: %llx\nState 2: %llx\n\n", state_1, state_2);
}




/***********************************************************************************************************/
void square_matrix_2n()
{
	u64 i = 0;
	u64 j = 0;
	u64 k = 0;
	u64 count = 0;
	
	u8 c_temp = 0;
	u64 l_temp = 0;
	u64 l_xor = 0;
	u64 one = 1;
	u64 zero = 0;
	
	u64 matrix_1[48];
	u64 matrix_2[48];
	
	// For time_index number of times, square the matrix transition_matrix_2n
	for(i = 0; i < time_index; i++)
	{
		//convert the matrix into array of u64
		for(j = 0; j < 48; j++)
		{
			for(k = 0; k < 48; k++)
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
		for(j = 0; j < 48; j++)
		{
			//printf("%llx ", matrix_1[j]);
		}
		
		//transpose of the matrix transition_matrix_2n 
		for(j = 0; j < 48; j++)
		{
			for(k = 0; k < 48; k++)
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
		printf("\n");
		for(j = 0; j < 48; j++)
		{
			for(k = 0; k < 48; k++)
			{
				//printf("%1x", transition_matrix_2n[j][k]);
			}
			//printf("\n");
		}
		//printf("\n");

		//convert the transposed matrix into u64 array
		for(j = 0; j < 48; j++)
		{
			for(k = 0; k < 48; k++)
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
		for(j = 0; j < 48; j++)
		{
			//printf("%llx %llx\n", matrix_1[j], matrix_2[j]);
		}
		
		//perform operations on the two u64 arrays and save the resultant value in the corresponding cell of the matrix
		for(j = 0; j < 48; j++)
		{
			for(k = 0; k < 48; k++)
			{
				// AND of the two rows
				l_temp = matrix_1[j] & matrix_2[k];
				
				
				l_xor = zero;
		
				for(count = 0; count < 48; count++)
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
	u64 l_temp;
	u64 l_xor;
	u64 one = 1;
	u64 zero = 0;
	
	u64 matrix_2[48];
	u64 state = *state_ptr;
	u64 new_state = 0;

	//print the squared matrix
	for(j = 0; j < 48; j++)
	{
		for(k = 0; k < 48; k++)
		{
			printf("%1x", transition_matrix_2n[j][k]);
		}
		printf("\n");
	}
	printf("\n");

	//convert the transition_matrix_2n matrix into u64 array
	for(j = 0; j < 48; j++)
	{
		for(k = 0; k < 48; k++)
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
	for(j = 0; j < 48; j++)
	{
		//printf("%12llx \n", matrix_2[j]);
	}

	//printf("State: %12llx \n", state);

	for(k = 0; k < 48; k++)
	{
		// AND of the two rows
		l_temp = matrix_2[k] & state;
		
		l_xor = zero;
		
		for(j = 0; j < 48; j++)
		{
			l_xor = l_xor ^ (l_temp >> (j));
		}

		//printf("%x ",(l_xor & one));
		new_state = new_state + ((l_xor & one) << (47 - k));
	}

	*state_ptr = new_state;	
}
