u64 hitag2_init(const u64 key, const u32 serial, const u32 IV)
{
   u32 i = 0;
   u64 x = ((key & 0xFFFF) << 32) + serial;

   for (i = 0; i < 32; i++)
   {
     x >>= 1;
     x += (u64) (f20(x)^(((IV >> i)^(key >> (i+16))) & 1)) << 47;
   }
   return x;
}



