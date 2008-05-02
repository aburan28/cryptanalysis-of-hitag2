     /*  Compile on MPE/iX 6.5.            */ 
     /*  With CCXL use "-Aa +e" or "-Ae".  */ 
     /*  With c89 use "-Wc,+e".            */ 
     #include <stdio.h>
     main(void)
     {
        unsigned long long bignumber = 0x1234567654321ULL; 
        printf("bignumber = %llx\n", bignumber);
        bignumber = bignumber * 0x1000000 + 0x123; 
        printf("bignumber = %llx\n", bignumber);
     }