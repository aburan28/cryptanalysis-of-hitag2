#include <stdio.h>
#include "../hitag2.c"

int main()
{
	u64 state;
	u64 prefix;
	u32 i = 0;
	
	state = 0x1aa0afda72f2ULL;
	printf("Current State: %llx\n", state);

	for(;i < 5808965; i++) hitag2_next_state(&state);

	printf("Current State: %llx\n", state);
	prefix = hitag2_prefix(&state, 48);
	printf("Prefix: %llx\n", prefix);
	
	return 1;
}
