
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

void prepare_keystream(u64 *);
void prepare_tags(u64 *);

void initialize_matrix();

void square_matrix_2n();		/* squares the state transition matrix n times (((A^2)^2) .. n times .. )^2 */

void compute_new_state(u64 *);		/* computes the new state from the new transition matrix by A.State */
void mapping_function(u64 *, u32);
u64 get_random(u32);
u64 get_random_32();

int tmto_keystream_attack(u32, u32, u32, u32, u32, u32);
int tmto_tags_attack(u32, u32, u32, u32, u32);
int tmdto_hellman_attack(u32, u32, u32, u32, u32, u32, u32, u32);
