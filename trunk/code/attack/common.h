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

#define TMTO_KEYSTREAM_ATTACK 	1
#define TMTO_TAGS_ATTACK 	2
#define TMDTO_HELLMAN_ATTACK 	3
#define TMDTO_RAINBOW_ATTACK 	4

#define RANDOM_MEMORY		5
#define NON_RANDOM_MEMORY	6

#define KEY1			0x49D2AC801F94ULL
#define KEY2			0xD4E98D3DA2F2ULL
#define KEY3			0x52B49EA34972ULL	

#define SERIAL_ID		0x69574349
#define INITIALIZATION_VECTOR	0x69574349
