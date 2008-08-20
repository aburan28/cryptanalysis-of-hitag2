/*
 *	This program is used to execute a Babbage-Golic time-memory
 *	tradeoff attack on the HiTag2 stream cipher
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>		/* for power function */
#include <time.h>
#include <string.h>		/* for memcpy */

#include "hashtable.h"		/* for hashtable prototypes */
#include "common.h"		/* for common declarations */
#include "hitag2.h"		/* for hitag2 function prototypes */
#include "attack_helper.h"	/* for helper function prototypes */
#include "attack_dispatcher.h"


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

int tmto_keystream_attack()
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

	/* allocate memory for keystream */
	c_keystream = (u64 *)malloc(sizeof(u64) * (D/64 + 1));

	/* if non-random memory is to be setup - initialize the matrices */
	if(memory_setup == NON_RANDOM_MEMORY)
	{
		/* Initializing the matrices */
		printf("\n\nInitializing state transition matrix ...");

		time(&time1);
		initialize_matrix();
		time(&time2);

		sec_diff = difftime(time2,time1);
		printf("\nTIME for initializing state transition matrix: %d ", sec_diff);
	}

	/* prepare the hashtable */
	printf("\n\nPreparing Hashtable ...");

	time(&time1);
	h = hash_table_setup();
	time(&time2);
	sec_diff = difftime(time2,time1);
	
	printf("\nTIME for preparing Hashtable: %d ", sec_diff);

	/* Check the size of the hashtable matches the M */
	if (M != hashtable_count(h))
	{
		printf("\nError: Size of Hashtable not correct ...");
		return 1;
	}

	/* Prepare a long keystream */
	printf("\n\nPreparing Keystream ...");

	time(&time1);
	prepare_keystream(c_keystream);
	keystream = *c_keystream;
	time(&time2);
	sec_diff = difftime(time2,time1);
	
	printf("\nTIME for preparing keystream: %d ", sec_diff);

	/* Starting Attack */
	printf("\n\nAttacking ...");
	time(&time1);
	k = (struct key *)malloc(sizeof(struct key));
	if (NULL == k)
	{
		printf("\nError: Ran out of memory allocating a key ...");
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

			printf("\n\nMatch Found! \nCurrent State: %llx  ", found_current_state);
			printf("Prefix: %llx\n", prefix);
			printf("\nPercentage of the worst case time: %f ", (i*100.00)/T);
			printf("I: %d\n", i);

			// Find the Initial State.
			for(j = 0; j < i; j++)
				hitag2_prev_state(&found_initial_state);

			printf("\nFound Initial State: %llx", found_initial_state);

			// Find the Key
			found_key = hitag2_find_key(found_initial_state, serial_id, init_vector);
			printf("\nFound Key: %llx", found_key);

			matched = 1;
		}
	}

	if(matched == 0) printf("\n\nNo Internal State found ...\n");

	time(&time2);
	sec_diff = difftime(time2,time1);
	
	printf("\nTIME for attack: %d", sec_diff);

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

	const u64 starting_state = 0x69574AD004ACULL;
	u64 state = 0;
	u64 pre_state = 0;

	u64 i = 0;
	u64 prefix = 0;

	/* create the hashtable */
	h = create_hashtable(M, hashfromkey, equalkeys);
	if (NULL == h) exit(-1); /* exit on error*/

	/* initialize the state to constant starting state */
	state = starting_state;

	if(memory_setup == NON_RANDOM_MEMORY)
	{

		for(i = 0; i < P; i++)
		{
			/* save the starting state */
			pre_state = state;

			/* call hitag2 prefix function */
			prefix = hitag2_prefix(&state, prefix_bits);

			k = (struct key *)malloc(sizeof(struct key));
			if (NULL == k)
			{
				printf("\nError: Could not allocate memory for prefix ...");
				exit(1);
			}

			k->key = prefix;
			v = (struct value *)malloc(sizeof(struct value));
			v->value = pre_state;
			
			/* insert (prefix,state) pair in the hash table */
			if (!insert_some(h,k,v))
			{
				printf("\nError: Could not allocate memory for state ...");
				exit(-1); /*oom*/
			}

			state = pre_state;

			/* state jump function */
			compute_new_state(&state);
		}
	}
	
	else if(memory_setup == RANDOM_MEMORY)
	{
		for(i = 0; i < P; i++)
		{
			/* get a random state */
			state = get_random(N);
			pre_state = state;
			
			/* call hitag2 prefix function */
			prefix = hitag2_prefix(&state, prefix_bits);

			k = (struct key *)malloc(sizeof(struct key));
			if (NULL == k)
			{
				printf("\nError: Could not allocate memory for prefix ...");
				exit(1);
			}

			k->key = prefix;
			v = (struct value *)malloc(sizeof(struct value));
			v->value = pre_state;
			
			/* insert (prefix,state) pair in the hash table */
			if (!insert_some(h,k,v))
			{
				printf("\nError: Could not allocate memory for state ...");
				exit(-1); /*oom*/
			}
		}
	}
	
	else
	{
		printf("\nError: Illegal option for memory setup ...");
		exit(1);
	}

	printf("\nPreparation of Hashtable complete ...");
	return h;
}
