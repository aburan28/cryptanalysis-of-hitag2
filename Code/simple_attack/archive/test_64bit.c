     /*  Compile on MPE/iX 6.5.            */ 
     /*  With CCXL use "-Aa +e" or "-Ae".  */ 
     /*  With c89 use "-Wc,+e".            */ 
     #include <stdio.h>
     main(void)
     {
        unsigned long long bignumber = 0x1234567654321ULL; 
        unsigned long long bignumber2 = 0x21000124ULL; 
        int i = 0;
        
        printf("bignumber = %llx\n", bignumber);
        bignumber = bignumber * 0x1000000 + 0x123; 
        printf("bignumber = %llx\n", bignumber);
        printf("bignumber = %d\n", sizeof(bignumber));
        
        if(bignumber == bignumber2) printf("\n This should not happen! ");
             
        for(; i < 32; i++)     
        {
        	printf("bignumber = %llx\n", bignumber >> 4*(i+1));	
        }
     }