#include <stdio.h>
#include <stdlib.h>
#include <math.h>		/* for power function */
#include <time.h>

#include "common.h"		/* for common definitions */
#include "attack_dispatcher.h"	
#include "attack_helper.h"

int main(int argc, char *argv[])
{
	time_t time1;
	
	attack_type = atoi(argv[1]);

	time(&time1);
	
	printf("\n\n-----------------------------------------");
	printf("\nTime of attack: %s", ctime(&time1));
	printf("-----------------------------------------");
	
	//secret_key = 0x52B49EA34972ULL;
	//secret_key = 0x49D2AC801F94ULL;
	secret_key = 0xD4E973ADA2F2ULL;

	serial_id = 0x69574349; 
	init_vector = 0x72456E65;
	
	N = 48;
	
	printf("\n\n**** Secret key used: 0x%llx ****\n", secret_key);

	if(attack_type == TMTO_KEYSTREAM_ATTACK)
	{
		M = pow(2,22);
		T = pow(2,26);
		P = M;
		D = T;
		prefix_bits = 48;
		memory_setup = RANDOM_MEMORY;

		/* print the attack parameters */
		printf("\n\nAttack type: TMTO KEYSTREAM ATTACK");
		printf("\nM = 2 power %u", (u32) log2(M));
		printf("\nT = 2 power %u", (u32) log2(T));
		printf("\nP = 2 power %u", (u32) log2(P));
		printf("\nD = 2 power %u", (u32) log2(D));
		printf("\nprefix_bits = %u", prefix_bits);
		
		if(memory_setup == RANDOM_MEMORY) printf("\nmemory_setup = RANDOM_MEMORY");
		else printf("\nmemory_setup = NON_RANDOM_MEMORY");		
		
		/* call the attack module */
		tmto_keystream_attack();
	}

	else if(attack_type == TMTO_TAGS_ATTACK)
	{
		M = pow(2,20);
		T = pow(2,26);
		P = M;
		D = T;
		prefix_bits = 32;

		/* print the attack parameters */
		printf("\n\nAttack type: TMTO TAGS ATTACK");
		printf("\nM = 2 power %u", (u32) log2(M));
		printf("\nT = 2 power %u", (u32) log2(T));
		printf("\nP = 2 power %u", (u32) log2(P));
		printf("\nD = 2 power %u", (u32) log2(D));
		printf("\nprefix_bits = %u", prefix_bits);

		/* call the attack module */
		tmto_tags_attack();
	}
	
	else if(attack_type == TMDTO_HELLMAN_ATTACK)
	{
		/* independent parameters */
		m = pow(2,18);
		t = pow(2,15);
		D = pow(2,14);

		/* dependent parameters */
		r = t/D;
		M = (m*t)/D;
		T = t*t;
		P = (m*t*t)/D;

		prefix_bits = 48;
		
		/* call the attack module */
		tmdto_hellman_attack(M, T, P, D, m, t, r, prefix_bits);
	}
	
	else if(attack_type == TMDTO_RAINBOW_ATTACK)
	{
		/* independent parameters */
		M = pow(2,24);
		t = pow(2,24);
		D = pow(2,16);

		/* dependent parameters */
		
		T = t*t/(4*D);
		t = t/D;
		
		prefix_bits = 48;
		
		/* call the attack module */
		tmdto_rainbow_attack(M, T, P, D, m, t, prefix_bits);
	}

}
