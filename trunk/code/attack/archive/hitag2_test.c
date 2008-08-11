#include <stdio.h>
#include "../hitag2.c"

int main()
{
	u64 state;
	u64 prefix;
	u64 found_key = 0;
	u32 i = 0;
	
	state = 0x5d8f8b67723cULL;
	printf("Current State: %llx\n", state);

	for(;i < 48; i++) hitag2_prev_state(&state);

	printf("Current State: %llx\n", state);
	found_key = hitag2_find_key(state, rev32 (0x69574349), rev32 (0x72456E65));
	printf("\nFound Key: %llx", rev64(found_key));
	
	return 1;
}
