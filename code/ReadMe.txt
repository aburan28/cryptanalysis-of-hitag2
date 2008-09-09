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


**********************************
STEPS FOR PRECOMPUTING THE TABLES
**********************************
(all the following commands are run from the directory ./attack/)

For creating a new Hellman or rainbow precomputation file, the programs "hellman_table_setup.c" and "rainbow_table_setup.c" can be used respectively. The parameters of the precomputation phase are replaced with the desired parameters in these files. These programs use functions from the HiTag2 library (to get prefix for a state), hence they are compiled using the following shell command:

% gcc -o hellman_table_setup hellman_table_setup.c hitag2.c
% gcc -o rainbow_table_setup rainbow_table_setup.c hitag2.c

After compilation, they can be run using:

% ./hellman_table_setup
% ./rainbow_table_setup


******************************
STEPS FOR RUNNING THE ATTACKS
******************************
(all the following commands are run from the directory ./attack/)

1. The first step is to change the attack parameters in the file "attack_dispatcher.c" corresponding to the specific attack to be run.

2. If a TMDTO attack is to be run, then the appropriate name of the precomputation file is replaced in the file "tmdto_hellman_attack.c" or "tmdto_rainbow_attack.c", so that the correct precomputation table is inserted into the hashtable during the attack. 

3. Once the parameters for the desired attack are set through the above steps, the executable "attack_dispatcher" is compiled using the command "make" on a Linux or Solaris machine. 

4. The executable is then called with an appropriate parameter indicating the attack to be run. The following command is executed on a shell for the specific attack to start:
% ./attack_dispatcher 1 - TMTO keystream attack is launched 
% ./attack_dispatcher 2 - TMTO tags attack is launched
% ./attack_dispatcher 3 - TMDTO hellman attack is launched
% ./attack_dispatcher 4 - TMDTO rainbow attack is launched

5. The output of the attack can be seen on the terminal. If the output is huge for the terminal, then the output could be redirected to a specific file using the >> identifier in the shell. 


******
NOTES
******

1. The attack program is guaranteed to run on Linux or Solaris operating systems. Compilation cannot be guaranteed on Windows. Still, if "gcc" and the "mingw32-make" utility is available on Windows, then the "attack_dispatcher" executable can be compiled. However, the output of the attack program would be restricted to 32 bit values, and hence only 32 bits of the 48 bit values (state or prefix) would be printed on the DOS prompt. This is due to an error in the "printf" function while displaying 64 bit values, which works fine only on 64-bit architectures like Solaris.

2. We have not been able to improve the reliability of the attack program. Hence, not many checks are performed in the program and in some cases the program might not give the appropriate error messages before terminating.