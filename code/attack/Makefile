#all: tmto_simple_attack tmto_adv_attack tmdto_attack

attack_dispatcher: hashtable.o hitag2.o tmto_keystream_attack.o tmto_tags_attack.o tmdto_hellman_attack.o attack_dispatcher.o attack_helper.o
	gcc -g -Wall -O -lm -o attack_dispatcher hashtable.o hitag2.o tmto_keystream_attack.o tmto_tags_attack.o tmdto_hellman_attack.o attack_dispatcher.o attack_helper.o

attack_dispatcher.o: attack_dispatcher.c common.h attack_dispatcher.h
	gcc -g -Wall -O -c attack_dispatcher.c -o attack_dispatcher.o

attack_helper.o: attack_helper.c common.h hitag2.h attack_helper.h
	gcc -g -Wall -O -c attack_helper.c -o attack_helper.o

tmdto_hellman_attack.o:	tmdto_hellman_attack.c common.h hitag2.h attack_helper.h
	gcc -g -Wall -O -c tmdto_hellman_attack.c -o tmdto_hellman_attack.o

tmto_tags_attack.o: tmto_tags_attack.c common.h hitag2.h attack_helper.h
	gcc -g -Wall -O -c tmto_tags_attack.c -o tmto_tags_attack.o

tmto_keystream_attack.o: tmto_keystream_attack.c common.h hitag2.h attack_helper.h
	gcc -g -Wall -O -c tmto_keystream_attack.c -o tmto_keystream_attack.o

hitag2.o: hitag2.c common.h hitag2.h
	gcc -g -Wall -O -c hitag2.c -o hitag2.o

hashtable.o: hashtable.c hashtable_private.h hashtable.h 
	gcc -g -Wall -O -c hashtable.c -o hashtable.o

tidy:
	rm *.o

clean: tidy
	rm -f tmto_keystream_attack tmto_tags_attack old_tmto_attack tmdto_hellman_attack
