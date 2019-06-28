SRC:=server.c
server:${SRC} Diffie_hellman.o
	gcc $< -o server Diffie_hellman.o aes/*.o -l gmp
Diffie_hellman.o:Diffie_hellman.c
	gcc -c Diffie_hellman.c -o Diffie_hellman.o
