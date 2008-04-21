
tmto_attack: hashtable.o tmto_attack.o hashtable_itr.o
	gcc -g -Wall -O -lm -o tmto_attack hashtable.o hashtable_itr.o tmto_attack.o

all: tmto_attack old_tmto_attack

tmto_attack.o:	tmto_attack.c
	gcc -g -Wall -O -c tmto_attack.c -o tmto_attack.o

old_tmto_attack: hashtable_powers.o tmto_attack.o hashtable_itr.o
	gcc -g -Wall -O -o old_tmto_attack hashtable_powers.o hashtable_itr.o tmto_attack.o

hashtable_powers.o:	hashtable_powers.c
	gcc -g -Wall -O -c hashtable_powers.c -o hashtable_powers.o

hashtable.o:	hashtable.c
	gcc -g -Wall -O -c hashtable.c -o hashtable.o

hashtable_itr.o: hashtable_itr.c
	gcc -g -Wall -O -c hashtable_itr.c -o hashtable_itr.o

tidy:
	rm *.o

clean: tidy
	rm -f tmto_attack old_tmto_attack
