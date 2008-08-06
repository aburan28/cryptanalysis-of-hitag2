#include<string.h>

#define TMTO_KEYSTREAM_ATTACK 	1
#define TMTO_TAGS_ATTACK 	2
#define TMDTO_HELLMAN_ATTACK 	3
#define TMDTO_RAINBOW_ATTACK 	4

#define RANDOM_MEMORY		5
#define NON_RANDOM_MEMORY	6













#define u8			unsigned char
#define u32			unsigned int
#define u64			unsigned long long
#define s32			signed int

#define rev8(x)			((((x)>>7)&1)+((((x)>>6)&1)<<1)+((((x)>>5)&1)<<2)+((((x)>>4)&1)<<3)+((((x)>>3)&1)<<4)+((((x)>>2)&1)<<5)+((((x)>>1)&1)<<6)+(((x)&1)<<7))
#define rev16(x)		(rev8 (x)+(rev8 (x>> 8)<< 8))
#define rev32(x)		(rev16(x)+(rev16(x>>16)<<16))
#define rev64(x)		(rev32(x)+(rev32(x>>32)<<32))
#define bit(x,n)		(((x)>>(n))&1)
#define bit32(x,n)		((((x)[(n)>>5])>>((n)))&1)
#define inv32(x,i,n)		((x)[(i)>>5]^=((u32)(n))<<((i)&31))
#define rotl64(x, n)		((((u64)(x))<<((n)&63))+(((u64)(x))>>((0-(n))&63)))
#define i4(x,a,b,c,d)		((u32)((((x)>>(a))&1)+(((x)>>(b))&1)*2+(((x)>>(c))&1)*4+(((x)>>(d))&1)*8))


struct key
{
    u64 key;
};

struct value
{
    u64 value;
};

u32 N;					/* number of bits in internal state */
u32 M;					/* memory for precomputation phase */
u32 T;					/* time for attack phase */
u32 P;					/* time for precomputation phase */
u32 D;					/* length of data available (bits)*/

u32 m;					/* number of the rows in each table */
u32 t;					/* length of each row in a table*/
u32 r;					/* number of tables */

u32 prefix_bits;			/* number of prefix bits */
u32 memory_setup;			/* '1' if the memory setup is random, else '0' */
					/* only used in tmto keystream attack */

u8 transition_matrix[48][48];		/* state transition matrix A */
u8 transition_matrix_2n[48][48];	/* matrix for computing state directly after 2^n transitions */


/* function prototypes here */
u64 hitag2_init(const u64, const u32, const u32);
u64 hitag2_find_key(u64, const u32, const u32);
void hitag2_prev_state(u64 *);
u64 hitag2_prefix(u64 *, u32);

void prepare_keystream(u64 *);
void prepare_tags(u64 *);

void initialize_matrix();

void square_matrix_2n();		/* squares the state transition matrix n times (((A^2)^2) .. n times .. )^2 */

void compute_new_state(u64 *);		/* computes the new state from the new transition matrix by A.State */
void mapping_function(u64 *, u32);
u64 get_random(u32);

int tmto_keystream_attack(u32, u32, u32, u32, u32, u32);
int tmdto_hellman_attack(u32, u32, u32, u32, u32, u32, u32, u32);
