/* Single bit Hitag2 functions */

static const u32 ht2_f4a = 0x2C79;		/* 0010 1100 0111 1001 */
static const u32 ht2_f4b = 0x6671;		/* 0110 0110 0111 0001 */
static const u32 ht2_f5c = 0x7907287B;		/* 0111 1001 0000 0111 0010 1000 0111 1011 */


u64 hitag2_init(const u64, const u32, const u32);
u64 hitag2_find_key(u64, const u32, const u32);
void hitag2_prev_state(u64 *);
u64 hitag2_prefix(u64 *, u32);
