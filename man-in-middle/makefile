main-in-middle:main.c Diffie_hellman.o
	gcc main.c -o man-in-middle Diffie_hellman.o aes/*.o -l gmp -l pcap
Diffie_hellman.o:Diffie_hellman.c
	gcc -c Diffie_hellman.c -o Diffie_hellman.o
