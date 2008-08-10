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
#include <math.h>		/* for power function */
#include <time.h>

#include "hashtable.h"		/* for hashtable */
#include "common.h"		/* for common definitions */
#include "hitag2.h"		/* for hitag2 function prototypes */
#include "attack_helper.h"	/* for helper function prototypes */

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
	
int tmto_tags_attack(u32 _M, u32 _T, u32 _P, u32 _D, u32 _prefix_bits)
{
	time_t time1, time2;
	u32 sec_diff = 0;
	u64 * c_tags;
	u64 prefix = 0;
	u32 i = 0;
	u32 j = 0;
	u32 matched = 0;
	u64 found_current_state = 0;
	u64 found_initial_state = 0;
	u64 found_key = 0;
	u32 iv = 0;

	struct value *found;
	struct key * k;
	struct hashtable *h;
	
	N = 48;

	/* initialize tradeoff variables */
	M = _M;
	T = _T;
	D = _D;
	P = _P;
	
	prefix_bits = _prefix_bits;
	
	time(&time1);
	printf("\nCurrent Time: %s", ctime(&time1));
	
	c_tags = (u64 *)malloc(sizeof(u64) * T * 2);
	
	/* Initializing the matrices */
	printf("\n\nInitializing matrices ...");
	time(&time1);
	initialize_matrix();
	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for initializing matrix: %d ", sec_diff);
	
	/* Prepare the hashtable */
	printf("\n\nPreparing Hashtable ...");
	time(&time1);
	h = hash_table_setup();
	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for preparing Hashtable: %d ", sec_diff);
		
	/* Check the size of the hashtable matches M */
	if (M != hashtable_count(h)) 
	{
		printf("\nError: Size of Hashtable not correct ...");
        	return 1;
    	}
	
	/* Prepare a long keystream */
	printf("\n\nPreparing tags of length %d bits ...", prefix_bits);
	time(&time1);
	prepare_tags(c_tags);
	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for preparing tags: %d ", sec_diff);

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
		prefix = *c_tags;
		iv = *(c_tags + 1);
		
		//printf("\nCurrent Prefix: %llX", prefix);
    		
		k->key = prefix;
        
		/* Call the hashtable method with key */
		found = search_some(h,k);

		if(found != NULL)
		{
			found_current_state = found->value;
			found_initial_state = found_current_state;

			printf("\nA Tag Found! State: %llx for Tag: %llx", found_current_state, prefix);
			//printf("%llx ", prefix);
			// Find the Key for the Internal State
			found_key = hitag2_find_key(found_current_state, 0x69574349, iv);
			printf(" Found Key: %llx\n", found_key);			
			matched = 1;
		}

		c_tags = c_tags + 2;
	}
		
	if(matched == 0)
		printf("\n\nNo Internal State found ...\n");

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for attack: %d", sec_diff);
	
	hashtable_destroy(h, 1);
	free(k);
	free(found);
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
	
	printf("\nCreating the Hashtable ...");
	// initialize the hash table
	h = create_hashtable(M, hashfromkey, equalkeys);
	if (NULL == h) exit(-1); /* exit on error*/
	
	// Initialize the state, to some random value.
	state = 0x695ABCD471FCULL;

	/* It is important how we setup the hash table for this attack 
	 * One way could be to store states which are at a fixed distance from each other 
	 * Other way could be to store a consecutive set of states along with their tags */
	 
	for(i = 0; i < P; i++)
	{
		// Save the starting state
		pre_state = state;
		
		//call hitag function - get 'prefix_bits' number of bits of keystream (in u64 format)
		prefix = hitag2_prefix(&state, prefix_bits);
		
		//save prefix and state in the hash table
		k = (struct key *)malloc(sizeof(struct key));
		if (NULL == k) 
		{
			printf("\nError: Could not allocate memory for Prefix ...");
			exit(1);
		}

		k->key = prefix;
		v = (struct value *)malloc(sizeof(struct value));
		v->value = pre_state;
		if (!insert_some(h,k,v)) 
		{
			printf("\nError: Could not allocate memory for State ...");
			exit(-1); /*oom*/
		}
		
		//State transition function
		state = pre_state;
		compute_new_state(&state);
	}

	printf("\nCreation of Hashtable complete ...");
	return h;
}


