static u64 hitag2_round(u64 *state)
{
   u64 x = *state;

   x = (x >>  1) +
       ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
        ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
	^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
	^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1)
	<< 47);

   *state = x;
   return hitag2_output(x);
}

static u64 hitag2_output(const u64 x)
{
   u64	i5;

   i5 = ((ht2_f4a >> i4 (x, 1, 2, 4, 5)) & 1)* 1
      + ((ht2_f4b >> i4 (x, 7,11,13,14)) & 1)* 2
      + ((ht2_f4b >> i4 (x,16,20,22,25)) & 1)* 4
      + ((ht2_f4b >> i4 (x,27,28,30,32)) & 1)* 8
      + ((ht2_f4a >> i4 (x,33,42,43,45)) & 1)*16;

   return (ht2_f5c >> i5) & 1;
}



