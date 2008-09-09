/*
	This attack module is used to mount a TMDTO_RAINBOW_ATTACK on the HiTag2 stream cipher
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

/* static alias functions */
DEFINE_HASHTABLE_INSERT(insert_some, struct key, struct value);
DEFINE_HASHTABLE_SEARCH(search_some, struct key, struct value);

int tmdto_rainbow_attack()
{
	time_t time1, time2;
	u32 sec_diff = 0;
	u64 * c_keystream;
	u64 keystream = 0;
	u64 prefix = 0;
	u32 i = 0;
	u32 j = 0;
	u32 current_t = 0;
	u32 matched = 0;
	u64 current_state = 0;
	u64 temp_state = 0;
	u64 temp_prefix = 0;
	u64 found_initial_state = 0;
	u64 found_start_state = 0;
	u64 found_current_state = 0;
	u64 found_key = 0;
	u32 function_number = 0;
	u32 false_alarms_count = 0;
	
	struct value *found = NULL;
	struct key * k = NULL;
	struct hashtable *h = NULL;

	/* CHANGE the name of the precomutation file to be opened for the attack */
	fp = fopen("../tables/rainbow_table_M23_t9.dat", "r");
	if(fp == NULL)
	{
		printf("\nError: Could not open file for reading ...");
		exit(1);
	}

	/* verify the file is compatible with this attack parameters */
	fscanf(fp, "%d %d\n", &file_M, &file_t);
	if((file_M != M)||(file_t != t))
	{
		printf("\nError: Incompatible parameters from hashtable file ...\n");
		exit(1);
	}

	/* allocate memory for keystream */
	c_keystream = (u64 *)malloc(sizeof(u64) * (D/64 + 1));

	time(&time1);
	printf("\nCurrent Time: %s", ctime(&time1));
	
	/* Prepare the hashtables */
	printf("\n\nPreparing Hashtable ...");
	time(&time1);
	
	h = (struct hashtable *) hash_table_setup();

	/* Check the size of the hashtable matches M */
	if (M != hashtable_count(h))
	{
		printf("\nError: Size of Hashtable not correct ...\n");
       		exit(1);
	}

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for preparing hashtable: %d ", sec_diff);

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
		printf("\nError: Ran out of memory allocating a key ...\n");
       		return 1;
   	}

	/* Start searching prefixes in the hashtable */
	for(i = 0, j = 0; i < D; i++)
	{
		prefix = keystream >> 16;

		/* Shift the keystream by 1 bit for computing the next prefix */
		if((i % 64) == 0) c_keystream++;
		keystream = (keystream << 1) ^ ((* c_keystream >> (63 - (i % 64))) & 1);
		
		for(current_t = 0; current_t < t; current_t++)
		{
			function_number = current_t + 1;
			
			/* perform the permutation function on the prefix first (in this case, no permutation) */
			current_state = prefix ^ ((u64) function_number);

			for(j = 0; j < (t - (current_t + 1)); j++)
			{
				mapping_function(&current_state, (function_number + j + 1));
			}


			k->key = current_state;
				
			/* Call the hashtable method with key */
			found = search_some(h,k);
				
			if(found != NULL)
			{
				found_start_state = found->value;
				temp_state = found_start_state;

				for(j = 0; j < current_t; j++)
				{
					mapping_function(&temp_state, (j + 1));
				}

				found_current_state = temp_state;
				
				/* find prefix of the current state */
				temp_prefix = hitag2_prefix(&temp_state, prefix_bits);

				/* false alarm has occured */
				if(temp_prefix != prefix)
				{
					printf("\nFalse Alarm generated ...temp prefix: %llx, prefix: %llx", temp_prefix, prefix);
					false_alarms_count++;
					continue;
				}
				else
				{
					found_initial_state = found_current_state;

					/* Find the Initial State from the Current State of the LFSR */
					for(j = 0; j < i; j++)
						hitag2_prev_state(&found_initial_state);

					printf("\nMatch!\n");
					printf("\nStatus:- D: %u, Found column: %u", (i+1), (current_t + 1));
					printf("\nFound prefix: %llu", prefix);
					printf("\nFound Initial State: %llx", found_initial_state);

					/* Find the Key */
					found_key = hitag2_find_key(found_initial_state, serial_id, init_vector);
					printf("\nFound Key: %llx", found_key);

					time(&time2);
					sec_diff = difftime(time2,time1);
					printf("\nTIME since starting attack: %d\n", sec_diff);

					matched = 1;
				}
			}
		}
	}

	if(matched == 0)
		printf("\n\nNo Internal State found ...\n");

	time(&time2);
	sec_diff = difftime(time2,time1);
	printf("\nTIME for attack: %d", sec_diff);

	printf("\nCOUNT of false alarms: %d", false_alarms_count);

	hashtable_destroy(h, 1);
	free(k);
	free(found);

	return 0;
}

/****************************************************************************************************
 * Hash Table setup function
****************************************************************************************************/
static struct hashtable * hash_table_setup()
{
	struct key *k;
	struct value *v;
	struct hashtable *h;

	u64 start_state = 0;
	u64 end_state = 0;

	u64 current_m = 0;

	// initialize the hash table
	h = create_hashtable(M, hashfromkey, equalkeys);
	if (NULL == h) exit(-1); /* exit on error*/

	for(current_m = 0; current_m < M; current_m++)
	{
		/* retrieve the start_state and end_state from precomputed file */
		fscanf(fp, "%llu %llu\n", &start_state, &end_state);

		/* save start_state and end_state in the hash table */
		k = (struct key *)malloc(sizeof(struct key));
		if (NULL == k)
		{
			printf("\nError: Could not allocate memory for end_state ...");
			exit(1);
		}

		k->key = end_state;
		
		v = (struct value *)malloc(sizeof(struct value));
		if (NULL == v)
		{
			printf("\nError: Could not allocate memory for start_state ...");
			exit(1);
		}

		v->value = start_state;
		
		if (!insert_some(h,k,v))
		{
			printf("\nError: Could not insert element in hash table ...");
			exit(1);
		}
	}

	return h;
}

