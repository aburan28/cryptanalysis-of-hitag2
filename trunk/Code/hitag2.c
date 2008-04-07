// Software optimized 48-bit Philips/NXP Mifare Hitag2 PCF7936/46/47/52 stream cipher algorithm by I.C. Wiener 2006-2007.
// For educational purposes only.
// No warranties or guarantees of any kind.
// This code is released into the public domain by its author.

#include <stdio.h>

// Basic macros:

#define u8				unsigned char
#define u32				unsigned long
#define u64				unsigned __int64
#define rev8(x)			((((x)>>7)&1)+((((x)>>6)&1)<<1)+((((x)>>5)&1)<<2)+((((x)>>4)&1)<<3)+((((x)>>3)&1)<<4)+((((x)>>2)&1)<<5)+((((x)>>1)&1)<<6)+(((x)&1)<<7))
#define rev16(x)		(rev8 (x)+(rev8 (x>> 8)<< 8))
#define rev32(x)		(rev16(x)+(rev16(x>>16)<<16))
#define rev64(x)		(rev32(x)+(rev32(x>>32)<<32))
#define bit(x,n)		(((x)>>(n))&1)
#define bit32(x,n)		((((x)[(n)>>5])>>((n)))&1)
#define inv32(x,i,n)	((x)[(i)>>5]^=((u32)(n))<<((i)&31))
#define rotl64(x, n)	((((u64)(x))<<((n)&63))+(((u64)(x))>>((0-(n))&63)))

// Single bit Hitag2 functions:

#define i4(x,a,b,c,d)	((u32)((((x)>>(a))&1)+(((x)>>(b))&1)*2+(((x)>>(c))&1)*4+(((x)>>(d))&1)*8))

static const u32 ht2_f4a = 0x2C79;		// 0010 1100 0111 1001
static const u32 ht2_f4b = 0x6671;		// 0110 0110 0111 0001
static const u32 ht2_f5c = 0x7907287B;	// 0111 1001 0000 0111 0010 1000 0111 1011

static u32 f20 (const u64 x)
{
	u32					i5;
	
	i5 = ((ht2_f4a >> i4 (x, 1, 2, 4, 5)) & 1)* 1
	   + ((ht2_f4b >> i4 (x, 7,11,13,14)) & 1)* 2
	   + ((ht2_f4b >> i4 (x,16,20,22,25)) & 1)* 4
	   + ((ht2_f4b >> i4 (x,27,28,30,32)) & 1)* 8
	   + ((ht2_f4a >> i4 (x,33,42,43,45)) & 1)*16;
	
	return (ht2_f5c >> i5) & 1;
}

static u64 hitag2_init (const u64 key, const u32 serial, const u32 IV)
{
	u32					i;
	u64					x = ((key & 0xFFFF) << 32) + serial;
	
	for (i = 0; i < 32; i++)
	{
		x >>= 1;
		x += (u64) (f20 (x) ^ (((IV >> i) ^ (key >> (i+16))) & 1)) << 47;
	}
	return x;
}

static u64 hitag2_round (u64 *state)
{
	u64					x = *state;
	
	x = (x >>  1) +
	 ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
	  ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
	  ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
	  ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1) << 47);
	
	*state = x;
	return f20 (x);
}

// "MIKRON"		=  O  N  M  I  K  R
// Key			= 4F 4E 4D 49 4B 52		- Secret 48-bit key
// Serial		= 49 43 57 69			- Serial number of the tag, transmitted in clear
// Random		= 65 6E 45 72			- Random IV, transmitted in clear
//~28~DC~80~31	= D7 23 7F CE			- Authenticator value = inverted first 4 bytes of the keystream

// The code below must print out "D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6".
// The inverse of the first 4 bytes is sent to the tag to authenticate.
// The rest is encrypted by XORing it with the subsequent keystream.

static u64 hitag2_byte (u64 * x)
{
	u64 i, c;
	
	for (i = 0, c = 0; i < 8; i++) c += (u64) hitag2_round (x) << (7 - i);
	return c;
}

static u64 hitag2_prefix(u64 * x)
{
	u64 i;
	u64 prefix = 0;

	for (i = 0; i < 6; i++) 
	{
		//prefix += (u64) hitag2_byte (x) << (5 - i)*8;
		printf("%llx ", (u64) hitag2_byte (x) << (5 - i)*8);	
	}
	
	return prefix;
}

int main (void)
{
	u32	i;
	u64	initial_state;
	u64	state;
	
	state = hitag2_init (rev64 (0x524B494D4E4F), rev32 (0x69574349), rev32 (0x72456E65));
	printf("Initial State: %lX\n", state);
	initial_state = state;
	
	for (i = 0; i < 16; i++) printf ("%02X ", hitag2_byte (&state));
	printf ("\n");
	
	state = initial_state;
	printf("Initial State: %lX\n", state);
	hitag2_prefix (&state);
	//printf ("%llu ", hitag2_prefix (&state));
	
	return 0;
}
