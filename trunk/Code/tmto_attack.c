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
#include "hitag2.c"
#include "hashtable.h"
#include "hashtable_itr.h"


void find_state(u64, u64 *);
void prepare_keystream(u64 *);
u64 * state_transition(u64 *, u32);
void square_matrix(u64 *);
struct hashtable * hash_table_setup(void);
	
u64 memory_complexity = 65536;	// 268435456 = 2^28
u64 time_complexity = 65536;	// 1048576 = 2^20

static u64 transition_matrix[48]; 

/*****************************************************************************/
struct key
{
    u64 key;
};

struct value
{
    u64 value;
};

DEFINE_HASHTABLE_INSERT(insert_some, struct key, struct value);
DEFINE_HASHTABLE_SEARCH(search_some, struct key, struct value);
DEFINE_HASHTABLE_REMOVE(remove_some, struct key, struct value);
DEFINE_HASHTABLE_ITERATOR_SEARCH(search_itr_some, struct key);

static unsigned int
hashfromkey(void *ky)
{
	struct key *k = (struct key *)ky;

	return (k->key % memory_complexity);
}

static int
equalkeys(void *k1, void *k2)
{
    return (0 == memcmp(k1,k2,sizeof(struct key)));
}

int main()
{
	u64 c_keystream[1025];
	u64 keystream = 0;
	u64 prefix = 0;
	u64 i = 0;
	u64 state = 0;
	u32 j = 0;

	struct value *found;
	struct key * k;
	struct hashtable *h;
	
	
	// Initialize the state transition matrix
	transition_matrix[0] = 0x400000000000ULL;
	for(i = 1; i < 47; i++)
	{
		transition_matrix[i] = transition_matrix[i-1] >> 1;
	}
	
	/* tap bits 0,2,3,6,7,8,16,22,23,26,30,41,42,43,46,47 */
	transition_matrix[47] = 0xBC1013220073ULL;
	
	/* Prepare the hashtable */
	h = hash_table_setup();
	
	/* Check the size of the hashtable matches the memory_complexity */
	if (memory_complexity != hashtable_count(h)) 
	{
		printf("\nError: Size of Hashtable not correct ...");
        	return 1;
    	}
	
	// Prepare longg keystream
	prepare_keystream(c_keystream);
		
	keystream = c_keystream[0];
	printf("\nKeystream: %llX %llX ... %llX %llX", c_keystream[0], c_keystream[1], c_keystream[1023], c_keystream[1024]);
	
	printf("\nStarting Attack ...");

	k = (struct key *)malloc(sizeof(struct key));
	if (NULL == k) 
	{
		printf("\nError: Ran out of memory allocating a key ...");
        	return 1;
    	}
	
	/* Start searching prefixes in the hashtable */
	for(i = 0, j = 0; i < time_complexity; i++)
	{
		prefix = keystream >> 16;

		//printf("\nCurrent Prefix: %llX", prefix);
    
		k->key = prefix;
        
		/* Call the hashtable method with key */
		found = search_some(h,k);

		/* Shift the keystream by 1 bit for computing the next prefix */
		if((i % 64) == 0) j = j + 1;
		keystream = (keystream << 1) ^ ((c_keystream[j] >> (63 - (i % 64))) & 1);
		
		if(found != NULL)
		{
			printf("\nMatch Found! Current State: %llx  Prefix: %llx\n", found->value, prefix);
			
			// Find the Initial State.
			
			// Find the Key for the Internal State
			
			exit(0);
		}
	}
	
	printf("\nNo Internal State Found");
	
	hashtable_destroy(h, 1);
	free(k);
	free(found);
}	

/****************************************************************************************************
 * Hash Table functions
****************************************************************************************************/ 

struct hashtable * hash_table_setup()
{
	struct key *k;
	struct value *v;
	struct hashtable *h;

	u64 state = 0;
	u64 pre_state = 0;
			
	u64 i = 0;
	u64 j = 0;
	u64 prefix = 0;
	
	printf("\nCreating the Hashtable ...");
	// initialize the hash table
	h = create_hashtable(memory_complexity, hashfromkey, equalkeys);
	if (NULL == h) exit(-1); /* exit on error*/
	
	// Initialize the state. This can be done also by randomly assigning a value to the state.
	state = hitag2_init (rev64 (0x524B494D4E4FULL), rev32 (0x69574349), rev32 (0x72456E65));

	
	for(i = 0; i < memory_complexity; i++)
	{
		// Save the starting state
		pre_state = state;
		
		//call hitag function - get 48 bits prefix (in u64 format)
		prefix = hitag2_prefix(&state);
		
		//save prefix and state in the hash table
		k = (struct key *)malloc(sizeof(struct key));
		if (NULL == k) 
		{
			printf("\nError: Could not allocate memory for Prefix");
			return 1;
		}

		k->key = prefix;
		v = (struct value *)malloc(sizeof(struct value));
		v->value = pre_state;
		if (!insert_some(h,k,v)) 
		{
			printf("\nError: Could not allocate memory for State");
			exit(-1); /*oom*/
		}

		//printf("\nInserted into Hashtable State: %llx  Prefix: %llx\n", pre_state, prefix);
		//State transition function
		
		//state = pre_state + 65536;
		//state = * state_transition(&pre_state, 8);
		
		for(j = 0; j < 48; j++)
		{
			hitag2_round(&state);
		}
		
	}

	printf("\nCreation of Hashtable complete ...");
	return h;
}

void prepare_keystream(u64 * c_keystream)
{
	u64 state = 0;
	u64 i = 0;
	
	// Initial State which needs to be determined..
	state = hitag2_init (rev64 (0x524B494D4E4FULL), rev32 (0x69574349), rev32 (0x72456E65));

	for(;i < time_complexity/64 + 1; i++)
	{
		*c_keystream = (u64) hitag2_u64(&state); 
		c_keystream++;
	}
	printf("\nKeystream made available ...");
}


u64 * state_transition(u64 *state, u32 n)
{
	u32 i = 0;


	u64 tm[48]; 
		
	for(i = 0; i < 48; i++)
	{
		tm[i] = transition_matrix[i];
	}
	
	// square matrix tm, n times
	for(i = 0; i < n; i++)
	{
		square_matrix(tm);
	}
	
	// find the new state from the transition matrix
	return state;
}

void square_matrix(u64 * matrix)
{
	u32 i = 0;
	
	for(i = 0; i < 48; i++)
	{
		
	}

}




