#include <stdio.h>
#include <stdlib.h>
#include <math.h>		/* for power function */
#include <time.h>

#include "common.h"		/* for common definitions */
#include "attack_dispatcher.h"	
#include "attack_helper.h"

int main(int argc, char *argv[])
{
	attack_type = atoi(argv[1]);
	
	if(attack_type == TMTO_KEYSTREAM_ATTACK)
	{
		M = pow(2,22);
		T = pow(2,26);
		P = M;
		D = T;
		prefix_bits = 48;
		memory_setup = RANDOM_MEMORY;
		tmto_keystream_attack(M, T, P, D, prefix_bits, memory_setup);
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
		tmdto_hellman_attack(M, T, P, D, m, t, r, prefix_bits);
	}
}
