#include <stdio.h>
#include <stdlib.h>
#include <math.h>		/* for power function */
#include <time.h>		/* for getting current time */

#include "common.h"		/* for common definitions */
#include "attack_dispatcher.h"	/* for declaration of attack parameters */
#include "attack_helper.h"	/* for helper function prototypes */

int main(int argc, char *argv[])
{
	time_t time1;
	
	attack_type = atoi(argv[1]);

	time(&time1);

	N = 48;
	
	/* SELECT the secret key from: KEY1, KEY2 OR KEY3 */
	secret_key = KEY2;
	
	serial_id = SERIAL_ID; 
	init_vector = INITIALIZATION_VECTOR;
	
	printf("\n\n-----------------------------------------");
	printf("\nTime of attack: %s", ctime(&time1));
	printf("-----------------------------------------");
	printf("\n\n**** Secret key used: 0x%llx ****\n", secret_key);

	if(attack_type == TMTO_KEYSTREAM_ATTACK)
	{
		/* CHANGE the parameters below */
		M = pow(2,21);
		T = pow(2,28);
		prefix_bits = 56;
		memory_setup = NON_RANDOM_MEMORY;

		/* following parameters are dependent on M, T */		
		P = M;
		D = T;

		/* print the attack parameters */
		printf("\n\nAttack type: TMTO KEYSTREAM ATTACK");
		printf("\nM = 2 power %u", (u32) log2(M));
		printf("\nT = 2 power %u", (u32) log2(T));
		printf("\nP = 2 power %u", (u32) log2(P));
		printf("\nD = 2 power %u", (u32) log2(D));
		printf("\nprefix_bits = %u", prefix_bits);
		
		if(memory_setup == RANDOM_MEMORY) printf("\nmemory_setup = RANDOM_MEMORY");
		else printf("\nmemory_setup = NON_RANDOM_MEMORY");		
		
		/* call the keystream attack module */
		tmto_keystream_attack();
	}

	else if(attack_type == TMTO_TAGS_ATTACK)
	{
		/* CHANGE the parameters below */
		M = pow(2,23);
		T = pow(2,27);

		/* following parameters are dependent on M, T */		
		P = M;
		D = T;

		/* FIXED parameter - DO NOT change */
		prefix_bits = 32;

		/* print the attack parameters */
		printf("\n\nAttack type: TMTO TAGS ATTACK");
		printf("\nM = 2 power %u", (u32) log2(M));
		printf("\nT = 2 power %u", (u32) log2(T));
		printf("\nP = 2 power %u", (u32) log2(P));
		printf("\nD = 2 power %u", (u32) log2(D));
		printf("\nprefix_bits = %u", prefix_bits);

		/* call the tags attack module */
		tmto_tags_attack();
	}
	
	else if(attack_type == TMDTO_HELLMAN_ATTACK)
	{
		/* CHANGE the parameters below */
		/* precomputation phase parameters */
		m = pow(2,12);
		t = pow(2,12);
		r = pow(2,8);
		
		/* attack phase parameters */
		D = pow(2,16);

		/* following parameters are dependent on m, t, r and D */
		M = m*r;
		P = m*t*r;
		T = t*r*D;		

		prefix_bits = 48;
		
		/* print the attack parameters */
		printf("\n\nAttack type: TMDTO HELLMAN ATTACK");
		printf("\nm = 2 power %u", (u32) log2(m));
		printf("\nt = 2 power %u", (u32) log2(t));
		printf("\nD = 2 power %u", (u32) log2(D));
		printf("\nM = 2 power %u", (u32) log2(M));
		printf("\nT = 2 power %u", (u32) log2(T));
		printf("\nP = 2 power %u", (u32) log2(P));
		printf("\nr = 2 power %u", (u32) log2(r));
		printf("\nprefix_bits = %u", prefix_bits);
		
		/* call the hellman attack module */
		tmdto_hellman_attack();
	}
	
	else if(attack_type == TMDTO_RAINBOW_ATTACK)
	{
		/* CHANGE the parameters below */
		/* precomputation phase parameters */
		M = pow(2,23);
		t = pow(2,9);
		
		/* attack phase parameters */
		D = pow(2,16);

		/* following parameters are dependent on M, t and D */
		P = M*t;
		T = (t*t*D)/2;
		
		prefix_bits = 48;
		
		/* print the attack parameters */
		printf("\n\nAttack type: TMDTO RAINBOW ATTACK");
		printf("\nM = 2 power %u", (u32) log2(M));
		printf("\nt = 2 power %u", (u32) log2(t));
		printf("\nD = 2 power %u", (u32) log2(D));
		printf("\nT ~ 2 power %u", (u32) log2(T));
		printf("\nP = 2 power %u", (u32) log2(P));
		printf("\nprefix_bits = %u", prefix_bits);
		
		/* call the rainbow attack module */
		tmdto_rainbow_attack();
	}
}
