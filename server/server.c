#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdio.h>
#include <sys/socket.h> 
#include <sys/types.h> 
#include "Diffie_hellman.h"
#define MAX 256 
#define PORT 8080 
#define SA struct sockaddr 

// Function designed for chat between client and server. 
void DH_key_exchange_server(int sockfd){
	Dh_key dh_key;
	//char buff[MAX];
    init_numbers(&dh_key);

    dh_key.urand = fopen("/dev/urandom","r");
    if(NULL == dh_key.urand)
    {
        fprintf(stderr, "Failed to init randomization\n");
        exit(1);
    }
    init_prime(64,&dh_key);
	//send prime
	char dh_str[MAX];
	bzero(dh_str,MAX);
	mpz_get_str(dh_str,16,dh_key.prime);
	write(sockfd,dh_str,sizeof(dh_str));
	//receive A
	bzero(dh_str,MAX);
	read(sockfd,dh_str,sizeof(dh_str));
	mpz_t key_from_c;
	mpz_init(key_from_c);
	mpz_set_str(key_from_c,dh_str,16);
	//calculate private key b 
    generate_key(64, &dh_key);
	//B=g^b(mod p)
    mpz_powm(dh_key.public_key, dh_key.base, dh_key.private_key, dh_key.prime);
	//send B
	bzero(dh_str,MAX);
	mpz_get_str(dh_str,16,dh_key.public_key);
	write(sockfd, dh_str, sizeof(dh_str));
	//calc s=g^(ab)
    mpz_powm(dh_key.key, key_from_c, dh_key.private_key, dh_key.prime);
	
	gmp_printf("%Zx\n",dh_key.key);
/*    char key_str[128];
    mpz_get_str(key_str,16,key_2);
    unsigned char * key_value=str2hex(key_str);*/
    fclose(dh_key.urand);
    clear_numbers(&dh_key);

}
void func(int sockfd) 
{ 
	char buff[MAX]; 
	int n; 
	// infinite loop for chat 
	DH_key_exchange_server(sockfd);
//	for (;;) { 
//		bzero(buff, MAX); 
//
//		// read the message from client and copy it in buffer 
//		read(sockfd, buff, sizeof(buff)); 
//		// print buffer which contains the client contents 
//		printf("From client: %s\t To client : ", buff); 
//		bzero(buff, MAX); 
//		n = 0; 
//		// copy server message in the buffer 
//		while ((buff[n++] = getchar()) != '\n') 
//			; 
//
//		// and send that buffer to client 
//		write(sockfd, buff, sizeof(buff)); 
//
//		// if msg contains "Exit" then server exit and chat ended. 
//		if (strncmp("exit", buff, 4) == 0) { 
//			printf("Server Exit...\n"); 
//			break; 
//		} 
//	} 
} 

// Driver function 
int main() 
{ 
	int sockfd, connfd, len; 
	struct sockaddr_in servaddr, cli; 

	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully created..\n"); 
	bzero(&servaddr, sizeof(servaddr)); 

	// assign IP, PORT 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(PORT); 

	// Binding newly created socket to given IP and verification 
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
		printf("socket bind failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully binded..\n"); 

	// Now server is ready to listen and verification 
	if ((listen(sockfd, 5)) != 0) { 
		printf("Listen failed...\n"); 
		exit(0); 
	} 
	else
		printf("Server listening..\n"); 
	len = sizeof(cli); 

	// Accept the data packet from client and verification 
	connfd = accept(sockfd, (SA*)&cli, &len); 
	if (connfd < 0) { 
		printf("server acccept failed...\n"); 
		exit(0); 
	} 
	else
		printf("server acccept the client...\n"); 

	// Function for chatting between client and server 
	func(connfd); 

	// After chatting close the socket 
	close(sockfd); 
} 

