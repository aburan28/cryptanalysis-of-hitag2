/*
 *	This program is used to execute a Babbage-Golic time-memory
 *	tradeoff attack on the HiTag2 stream cipher
 *
 *	HiTag2 parameters:
 *	Key	= 4F 4E 4D 49 4B 52
 *	Serial	= 49 43 57 69
 *	Random	= 65 6E 45 72
 *
 *	"D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6"
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>		/* for power function */
#include <time.h>

#include "hashtable.h"		/* for hashtable */
#include "common.h"		/* for common definitions */

static struct hashtable * hash_table_setup();

static int
equalkeys(void *k1, void *k2)
{
    return (0 == memcmp(k1,k2,sizeof(struct key)));
}

static unsigned int
hashfromkey(void *ky)
{
	struct key *k = (struct key *)ky;

	return (k->key % M);
}

DEFINE_HASHTABLE_INSERT(insert_some, struct key, struct value);
DEFINE_HASHTABLE_SEARCH(search_some, struct key, struct value);

u64 get_random(u32 bits)
{
	u32 i = 0;
	u64 random_number = 0;
	u64 rand_out = 0;

	for(i = 0; i < bits - 16; i++)
	{
		rand_out = rand() % 65535;
		random_number = (random_number << 1) ^ rand_out ^ (rand_out >> 1);
	}

	return random_number;
}

int tmto_keystream_attack(u32 _M, u32 _T, u32 _P, u32 _D, u32 _prefix_bits, u32 _memory_setup)
{
	time_t time1, time2;
	u32 sec_diff = 0;
	u64 * c_keystream;
	u64 keystream = 0;
	u64 prefix = 0;
	u32 i = 0;
	u32 j = 0;
	u32 matched = 0;
	u64 found_current_state = 0;
	u64 found_initial_state = 0;
	u64 found_key = 0;

	struct value *found = NULL;
	struct key * k = NULL;
	struct hashtable *h = NULL;

	/* initialize tradeoff variables */
	M = _M;
	T = _T;
	D = _D;
	P = _P;

	memory_setup = _memory_setup;
	prefix_bits = _prefix_bits;
	
	/* allocate memory for keystream */
	c_keystream = (u64 *)malloc(sizeof(u64) * (D/64 + 1));

	/* if non-random memory is to be setup - initialize the matrices */
	if(memory_setup == 0)
	{
		/* Initializing the matrices */
		printf("\n\nInitializing matrices ...");
		fflush(stdout);
		time(&time1);
		initialize_matrix();
		time(&time2);
		printf("\nCurrent Time: %s", ctime(&time1));
		fflush(stdout);
		sec_diff = difftime(time2,time1);
		printf("\nTIME for initializing matrix: %d ", sec_diff);
		fflush(stdout);
	}

	/* prepare the hashtable */
	printf("\n\nPreparing Hashtable ...");
	fflush(stdout);
	time(&time1);
	h = hash_table_setup();
	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for preparing Hashtable: %d ", sec_diff);
	fflush(stdout);

	/* Check the size of the hashtable matches the M */
	if (M != hashtable_count(h))
	{
		printf("\nError: Size of Hashtable not correct ...");
		fflush(stdout);
		return 1;
	}

	/* Prepare a long keystream */
	printf("\n\nPreparing Keystream ...");
	fflush(stdout);
	time(&time1);
	prepare_keystream(c_keystream);

	keystream = *c_keystream;

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for preparing keystream: %d ", sec_diff);
	fflush(stdout);

	/* Starting Attack */
	printf("\n\nAttacking ...");
	fflush(stdout);
	time(&time1);
	k = (struct key *)malloc(sizeof(struct key));
	if (NULL == k)
	{
		printf("\nError: Ran out of memory allocating a key ...");
		fflush(stdout);
        	return 1;
    	}

	/* Start searching prefixes in the hashtable */
	for(i = 0, j = 0; i < T; i++)
	{
		prefix = keystream >> (64 - prefix_bits);

		//printf("\nCurrent Prefix: %llX", prefix);

		k->key = prefix;

		/* Call the hashtable method with key */
		found = search_some(h,k);

		/* Shift the keystream by 1 bit for computing the next prefix */
		if((i % 64) == 0) c_keystream++;
		keystream = (keystream << 1) ^ ((* c_keystream >> (63 - (i % 64))) & 1);

		if(found != NULL)
		{
			found_current_state = found->value;
			found_initial_state = found_current_state;

			printf("\nMatch Found! Current State: %llx  ", found_current_state);
			printf("Prefix: %llx\n", prefix);
			printf("\nPercentage of the worst case time: %f ", (i*100.00)/T);
			printf("I: %d\n", i);
			fflush(stdout);

			// Find the Initial State.
			for(j = 0; j < i; j++)
				hitag2_prev_state(&found_initial_state);

			printf("\nFound Initial State: %llx", found_initial_state);
			fflush(stdout);

			// Find the Key
			found_key = hitag2_find_key(found_initial_state, rev32 (0x69574349), rev32 (0x72456E65));
			printf("\nFound Key: %llx", found_key);
			printf("\nFound Key: %llx", rev64(found_key));
			fflush(stdout);

			matched = 1;
			//break;
		}
	}

	if(matched == 0)
		printf("\n\nNo Internal State found ...\n");
		fflush(stdout);

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for attack: %d", sec_diff);
	fflush(stdout);

	hashtable_destroy(h, 1);
	free(k);
	free(found);

	return 0;
}

/****************************************************************************************************
 * Hash Table functions
****************************************************************************************************/

static struct hashtable * hash_table_setup()
{
	struct key *k;
	struct value *v;
	struct hashtable *h;

	u64 state = 0;
	u64 pre_state = 0;

	u64 i = 0;
	u64 prefix = 0;

	// initialize the hash table
	h = create_hashtable(M, hashfromkey, equalkeys);
	if (NULL == h) exit(-1); /* exit on error*/

	// Initialize the state, to some random value.
	state = 0x69574AD004ACULL;

	if(memory_setup == 0)
	{

		for(i = 0; i < P; i++)
		{
			// Save the starting state
			pre_state = state;

			//call hitag function - get prefix bits (in u64 format)
			prefix = hitag2_prefix(&state, prefix_bits);

			//save prefix and state in the hash table
			k = (struct key *)malloc(sizeof(struct key));
			if (NULL == k)
			{
				printf("\nError: Could not allocate memory for Prefix");
				fflush(stdout);
				exit(1);
			}

			k->key = prefix;
			v = (struct value *)malloc(sizeof(struct value));
			v->value = pre_state;
			if (!insert_some(h,k,v))
			{
				printf("\nError: Could not allocate memory for State");
				fflush(stdout);
				exit(-1); /*oom*/
			}

			/* State transition function */
			state = pre_state;

			compute_new_state(&state);
		}
	}
	else
	{
		for(i = 0; i < P; i++)
		{
			state = get_random(N);
			pre_state = state;
			
			//call hitag function - get prefix bits (in u64 format)
			prefix = hitag2_prefix(&state, prefix_bits);

			//save prefix and state in the hash table
			k = (struct key *)malloc(sizeof(struct key));
			if (NULL == k)
			{
				printf("\nError: Could not allocate memory for Prefix");
				fflush(stdout);
				exit(1);
			}

			k->key = prefix;
			v = (struct value *)malloc(sizeof(struct value));
			v->value = pre_state;
			if (!insert_some(h,k,v))
			{
				printf("\nError: Could not insert values into hashtable ...");
				fflush(stdout);
				exit(-1); /*oom*/
			}
		}
	}

	printf("\nPreparation of Hashtable complete ...");
	fflush(stdout);
	return h;
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
