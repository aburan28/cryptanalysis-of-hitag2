This ReadMe file provides information on:

1. The directory structure of the software
2. Listing of the attack programs
3. Steps for running the attacks

**********************
TOP LEVEL DIRECTORIES
**********************
-> ./attack/
Contains all the programs for the attack.

-> ./hash_table/
Contains the original implementation of hashtables by Christpher Clark.

-> ./results/
Contains the output of the attack programs for all the attacks. 

-> ./tables/
Contains all the precomputation tables for Hellman and rainbow attacks. 

****************
SUB-DIRECTORIES
****************
-> ./attack/archive/
Contains some small programs used for testing correctness of some aspects of the main program like generation of random numbers, state transition matrix etc. These programs are not part of the attack programs. 

-> ./results/<attack-name>/
Contains the outcome of the implementation for the specific attack given by the <attack-name>. Four sub-directories exist namely "tmto_kystream_attack", "tmto_tags_attack", "tmdto_hellman_attack" and "tmdto_rainbow_attack".

*******************************
LISTING OF THE ATTACK PROGRAMS
*******************************
-> ./attack/Makefile
Contains commands for creating the object files and finally linking them to create a common executable for all the attacks.

-> ./attack/common.h
Contains common definitions used in most of the object files.

-> ./attack/attack_dispatcher.c
Contains the main function.

-> ./attack/attack_dispatcher.h

-> ./attack/attack_helper.c
Contains various helper functions used in one or more of the attacks.

-> ./attack/attack_helper.h

-> ./attack/tmto_keystream_attack.c
This is the attack module for TMTO keystream attack. It is called from the "attack_dispatcher.c" program.

-> ./attack/tmto_tags_attack.c
This is the attack module for TMTO tags attack. It is called from the "attack_dispatcher.c" program.

-> ./attack/tmdto_hellman_attack.c
This is the attack module for TMDTO attack using Hellman tables. It is called from the "attack_dispatcher.c" program.

-> ./attack/tmdto_rainbow_attack.c
This is the attack module for TMDTO attack using rainbow table. It is called from the "attack_dispatcher.c" program.

-> ./attack/hitag2.c
This is the library of HiTag2 functions.

-> ./attack/hitag2.h

-> ./attack/hashtable.c
-> ./attack/hashtable.h
-> ./attack/hashtable_itr.c
-> ./attack/hashtable_itr.h
-> ./attack/hashtable_private.h
All these five files contain the hashtable implementation.

-> ./attack/hellman_table_setup.c
This program performs the precomputation of the Hellman tables given the parameters m,t and r.
It stores the table in a .dat file in the directory ./tables/ with the name of the file as "hellman_<m>_<t>_<r>.dat".

-> ./attack/rainbow_table_setup.c
This program performs the precomputation of the rainbow table given the parameters M and t. 
It stores the table in a .dat file in the directory ./tables/ with the name of the file as "rainbow_<M>_<t>.dat".

******************************
STEPS FOR RUNNING THE ATTACKS
******************************


