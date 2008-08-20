struct key
{
    u64 key;
};

struct value
{
    u64 value;
};

u8 transition_matrix[48][48];		/* update function matrix U */
u8 transition_matrix_2n[48][48];	/* state transition function matrix A */

FILE *fp;
u32 file_m;
u32 file_r;
u32 file_t;
u32 file_M;


/* function prototypes here */

void prepare_keystream(u64 *);
void prepare_tags(u64 *);

void initialize_matrix();

void square_matrix_2n();		/* squares the update function matrix n times (((A^2)^2) .. n times .. )^2 */

void compute_new_state(u64 *);		/* computes the new state from the state transition function matrix by A.State */
void mapping_function(u64 *, u32);
u64 get_random(u32);
u64 get_random_32();

int tmto_keystream_attack();
int tmto_tags_attack();
int tmdto_hellman_attack(u32, u32, u32, u32, u32, u32, u32, u32);
int tmdto_rainbow_attack(u32, u32, u32, u32, u32, u32, u32);
