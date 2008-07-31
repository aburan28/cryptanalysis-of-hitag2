/*
	This program is used to execute a time-memory tradeoff attack on the HiTag2 stream cipher
	Used parameters:
	Key	= 4F 4E 4D 49 4B 52
	Serial	= 49 43 57 69

	Available Keystream: 32 bit tags

	"D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6"
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h> 		/* for memcmp */
#include <math.h>			/* for power function */
#include "hitag2.c"			/* for hitag2 stream cipher operations */
#include "hashtable.h"		/* for hashtable */
#include <time.h>

void prepare_keystream(u64 *);
void mapping_function(u64 *, u32);
u64 get_random(u32);
struct hashtable * single_hash_table_setup(u32);

/* following parameters need to be set independently */
u32 N;				/* state size */
u32 m;				/* number of the rows in each table */
u32 t;				/* length of each row in a table*/
u32 D;				/* length of data available */

/* following parameters are calculated based on the above parameters */
u32 r;				/* number of tables */
u32 M;				/* memory for precomputation phase */
u32 P;				/* time for precomputation phase */
u32 T;				/* time for attack phase */

u32 prefix_bits;		/* number of bits considered from the prefix */

/*****************************************************************************/
struct key
{
    u64 key;
};

struct value
{
    u64 value;
};


static unsigned int
hashfromkey(void *ky)
{
	struct key *k = (struct key *)ky;

	return (k->key % m);
}

static int
equalkeys(void *k1, void *k2)
{
    return (0 == memcmp(k1,k2,sizeof(struct key)));
}


DEFINE_HASHTABLE_INSERT(insert_some, struct key, struct value);
DEFINE_HASHTABLE_SEARCH(search_some, struct key, struct value);
DEFINE_HASHTABLE_REMOVE(remove_some, struct key, struct value);

void initialize()
{
	/* independent parameters */
	m = pow(2,20);
	t = pow(2,14);
	D = pow(2,14);
	N = 48;
	prefix_bits = 48;

	/* dependent parameters */
	r = t/D;
	M = (m*t)/D;
	T = t*t;
	P = (m*t*t)/D;
}

int main()
{
	time_t time1, time2;
	u32 sec_diff = 0;
	u64 * c_keystream;
	u64 keystream = 0;
	u64 prefix = 0;
	u32 i = 0;
	u32 j = 0;
	u32 current_r = 0;
	u32 current_t = 0;
	u32 matched = 0;
	u64 current_state = 0;
	u64 temp_state = 0;
	u64 temp_prefix = 0;
	u64 found_initial_state = 0;
	u64 found_start_state = 0;
	u64 found_key = 0;

	struct value *found = NULL;
	struct key * k = NULL;
	struct hashtable *h = NULL;
	struct hashtable * hashtable_array[r];

	/* initialze the tradeoff parameters */
	initialize();

	/* allocate memory for keystream */
	c_keystream = (u64 *)malloc(sizeof(u64) * (D/64 + 1));

	printf("\nCurrent Time: %s", ctime(&time1));
	fflush(stdout);

	/**** Prepare the hashtables ****/
	printf("\n\nPreparing Hashtable ...");
	fflush(stdout);
	time(&time1);

	/* generate 'r' hashtables to store endpoints of each table */
	for(current_r = 0; current_r < r; current_r++)
	{
		hashtable_array[current_r] = (struct hashtable *) single_hash_table_setup(current_r + 1);

		/* Check the size of the hashtable matches the memory_complexity */
		if (m != hashtable_count(hashtable_array[current_r]))
		{
			printf("\nError: Size of Hashtable not correct ...");
			fflush(stdout);
        		return 1;
    		}
	}

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for preparing hashtable: %d ", sec_diff);
	fflush(stdout);

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
	for(i = 0, j = 0; i < D; i++)
	{
		prefix = keystream >> 16;

		/* Shift the keystream by 1 bit for computing the next prefix */
		if((i % 64) == 0) c_keystream++;
		keystream = (keystream << 1) ^ ((* c_keystream >> (63 - (i % 64))) & 1);

		/* run through all the 'r' tables */
		for(current_r = 0; current_r < r; current_r++)
		{
			//printf("\nTable %d being checked ...", current_r);
			h = hashtable_array[current_r];

			/* perform the permutation function on the prefix first (in this case, no permutation) */
			current_state = prefix;

			for(current_t = 0; current_t < t; current_t++)
			{
				k->key = current_state;
				/* Call the hashtable method with key */
				found = search_some(h,k);

				/* compute the next state in the chain */
				mapping_function(&current_state, current_r);

				if(found != NULL)
				{
					found_start_state = found->value;
					temp_state = found_start_state;

					for(j = 0; j < t - (current_t + 1); j++)
					{
						mapping_function(&temp_state, current_r);
					}

					/* find prefix of the current state */
					temp_prefix = hitag2_prefix(&temp_state, prefix_bits);

					/* false alarm has occured */
					if(temp_prefix != prefix)
					{
						printf("\nFalse Alarm generated ...");
						fflush(stdout);
						continue;
					}
					else
					{
						/* Find the Initial State */
						found_initial_state = temp_state;
						for(j = 0; j < i; j++)
							hitag2_prev_state(&found_initial_state);

						printf("\nFound Initial State: %llx", found_initial_state);
						fflush(stdout);

						/* Find the Key */
						found_key = hitag2_find_key(found_initial_state, rev32 (0x69574349), rev32 (0x72456E65));
						printf("\nFound Key: %llx", found_key);
						printf("\nFound Key: %llx", rev64(found_key));
						fflush(stdout);

						matched = 1;
						break;
					}

				}
			}
		}
	}

	if(matched == 0)
		printf("\n\nNo Internal State found ...\n");
		fflush(stdout);

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for attack: %d", sec_diff);
	fflush(stdout);

	for(i = 0; i < r; i++)
	{
		hashtable_destroy(hashtable_array[i], 1);
	}
	free(k);
	free(found);

	return 0;
}

/****************************************************************************************************
 * Hash Table setup function
****************************************************************************************************/
struct hashtable * single_hash_table_setup(u32 table_number)
{
	struct key *k;
	struct value *v;
	struct hashtable *h;

	u64 start_state = 0;
	u64 end_state = 0;

	u64 i = 0;
	u64 j = 0;

	printf("\nCreating the Hashtable ...");
	fflush(stdout);

	// initialize the hash table
	h = create_hashtable(m, hashfromkey, equalkeys);
	if (NULL == h) exit(-1); /* exit on error*/


	/* It is important how we setup the hash table for this attack
	 * One way could be to store states which are at a fixed distance from each other
	 * Other way could be to store a consecutive set of states along with their tags */

	for(i = 0; i < m; i++)
	{
		// Initialize the state, to some random value.
		start_state = get_random(N);

		// Save the starting state
		end_state = start_state;

		for(j = 0; j < t; j++)
		{
			mapping_function(&end_state, table_number);
		}

		//save prefix and state in the hash table
		k = (struct key *)malloc(sizeof(struct key));
		if (NULL == k)
		{
			printf("\nError: Could not allocate memory for Prefix ...");
			fflush(stdout);
			exit(1);
		}

		k->key = end_state;
		v = (struct value *)malloc(sizeof(struct value));
		v->value = start_state;
		if (!insert_some(h,k,v))
		{
			printf("\nError: Could not allocate memory for State ...");
			fflush(stdout);
			exit(-1); /*oom*/
		}
	}

	printf("\nCreation of Hashtable %d complete ...", table_number);
	fflush(stdout);

	return h;
}

/*
u64 get_random()
{
	u64 random_number = 0;

	random_number = rand() % 4294967295;
	if(random_number == 0)
		random_number = get_random();

	return random_number;
}
*/

void prepare_keystream(u64 * c_keystream)
{
	u64 state = 0;
	u64 i = 0;

	/* Randomly select a key, a IV and a Serial ID; to determine the initial state */
	state = hitag2_init (rev64 (0x524B494D4E4FULL), rev32 (0x69574349), rev32 (0x72456E65));

	for(;i < D/64 + 1; i++)
	{
		*c_keystream = (u64) hitag2_prefix(&state, 64);
		c_keystream++;
	}
	printf("\nKeystream made available ...");
	fflush(stdout);
}

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
	*state = prefix;
}
