#all: tmto_simple_attack tmto_adv_attack tmdto_attack

tmdto_attack: hashtable.o hitag2.o tmdto_attack.o 
	gcc -g -Wall -O -lm -o tmdto_attack hashtable.o tmdto_attack.o hitag2.o 

tmto_adv_attack: hashtable.o hitag2.o tmto_adv_attack.o  
	gcc -g -Wall -O -lm -o tmto_adv_attack hashtable.o tmto_adv_attack.o hitag2.o 

tmto_simple_attack: hashtable.o hitag2.o tmto_simple_attack.o  
	gcc -g -Wall -O -lm -o tmto_simple_attack hashtable.o hitag2.o tmto_simple_attack.o 

hitag2.o: hitag2.c
	gcc -g -Wall -O -c hitag2.c -o hitag2.o

tmdto_attack.o:	tmdto_attack.c
	gcc -g -Wall -O -c tmdto_attack.c -o tmdto_attack.o

tmto_simple_attack.o:	tmto_simple_attack.c
	gcc -g -Wall -O -c tmto_simple_attack.c -o tmto_simple_attack.o

tmto_adv_attack.o:	tmto_adv_attack.c
	gcc -g -Wall -O -c tmto_adv_attack.c -o tmto_adv_attack.o

old_tmto_attack: hashtable_powers.o tmto_attack.o
	gcc -g -Wall -O -o old_tmto_attack hashtable_powers.o tmto_attack.o

hashtable_powers.o:	hashtable_powers.c
	gcc -g -Wall -O -c hashtable_powers.c -o hashtable_powers.o

hashtable.o:	hashtable.c
	gcc -g -Wall -O -c hashtable.c -o hashtable.o

tidy:
	rm *.o

clean: tidy
	rm -f tmto_simple_attack tmto_adv_attack old_tmto_attack tmdto_attack
