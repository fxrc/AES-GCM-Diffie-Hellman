#include <openssl/dh.h>
#include <memory.h>

#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "Diffie_hellman.h"

#define MAX 256
#define PORT 8080
#define SA struct sockaddr

void DH_key_exchange_client(int sockfd){
    Dh_key client_key;
    init_numbers(&client_key);
	client_key.urand = fopen("/dev/urandom","r");
    mpz_set_ui(client_key.base, (unsigned long)2);
	char buff[MAX];
	memset(buff,0,MAX);
	//receive prime
	memset(buff,0,MAX);    
	read(sockfd,buff,sizeof(buff));
    mpz_set_str(client_key.prime,buff,16);
    //generate private key a
	generate_key(64, &client_key);
	//calculate public key A=g^a(mod p)
	mpz_powm(client_key.public_key, client_key.base, client_key.private_key, client_key.prime);
	//send A
	bzero(buff,MAX);	
	mpz_get_str(buff,16,client_key.public_key);
	write(sockfd,buff,sizeof(buff));
	//receive B
	bzero(buff,MAX);
	read(sockfd,buff,sizeof(buff));
	mpz_t key_from_s;
	mpz_init(key_from_s);
	mpz_set_str(key_from_s,buff,16);
	//calc s=g^(ab)
    mpz_powm(client_key.key, key_from_s, client_key.private_key, client_key.prime);
	gmp_printf("%Zx\n",client_key.key);
}
void func(int sockfd)
{
	char buff[MAX];
	int n;
	DH_key_exchange_client(sockfd);

//	for (;;) {
//		bzero(buff, sizeof(buff));
////		printf("Enter the string : ");
////		n = 0;
////		while ((buff[n++] = getchar()) != '\n')
////			;
////		write(sockfd, buff, sizeof(buff));
//		bzero(buff, sizeof(buff));
//		read(sockfd, buff, sizeof(buff));
//		printf("From Server : %s", buff);
//		if ((strncmp(buff, "exit", 4)) == 0) {
//			printf("Client Exit...\n");
//			break;
//		}
//	}
}

int main()
{
	int sockfd, connfd;
	struct sockaddr_in servaddr, cli;

	// socket create and varification
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
	servaddr.sin_addr.s_addr = inet_addr("192.168.166.141");
	servaddr.sin_port = htons(PORT);

	// connect the client socket to server socket
	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
		printf("connection with the server failed...\n");
		exit(0);
	}
	else
		printf("connected to the server..\n");

	// function for chat
	func(sockfd);

	// close the socket
	close(sockfd);
}
