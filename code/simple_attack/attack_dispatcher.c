#include <stdio.h>
#include <stdlib.h>
#include <math.h>		/* for power function */
#include <time.h>

#include "common.h"		/* for common definitions */

u32 attack_type = 0;
u32 M = 0;
u32 T = 0;
u32 D = 0;
u32 P = 0;
u32 m = 0;
u32 t = 0;
u32 r = 0;

u32 prefix_bits = 0;
u32 memory_setup = 0;

int main(int argc, char *argv[])
{
	attack_type = atoi(argv[1]);
	printf("herherihewoiudf");
	
	if(attack_type == TMTO_KEYSTREAM_ATTACK)
	{
		M = pow(2,22);
		T = pow(2,26);
		P = M;
		D = T;
		prefix_bits = 48;
		memory_setup = NON_RANDOM_MEMORY;
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
