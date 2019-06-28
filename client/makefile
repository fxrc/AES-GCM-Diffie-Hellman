SRC:=client.c
client:${SRC} Diffie_hellman.o aes/*.o
	gcc ${SRC} -o client Diffie_hellman.o aes/*.o -l gmp
Diffie_hellman.o:Diffie_hellman.c
	gcc -c Diffie_hellman.c -o Diffie_hellman.o
