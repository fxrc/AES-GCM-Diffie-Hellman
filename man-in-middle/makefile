main-in-middle:man-in-middle.c Diffie_hellman.o
	gcc man-in-middle.c -o man-in-middle Diffie_hellman.o aes/*.o -l gmp
Diffie_hellman.o:Diffie_hellman.c
	gcc -c Diffie_hellman.c -o Diffie_hellman.o
