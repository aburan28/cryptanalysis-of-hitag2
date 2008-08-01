#include <stdio.h>
#include "../hitag2.c"

int main()
{
	u64 state;
	u64 key;
	
	state = hitag2_init(rev64 (0x524B494D4E4FULL), rev32 (0x69574349), rev32 (0x72456E65));
	printf("Current State: %llx\n", state);

	key = hitag2_find_key(state, rev32 (0x69574349), rev32 (0x72456E65));
	printf("Found Key: %llx\n", rev64(key));
	
	return 1;
}
