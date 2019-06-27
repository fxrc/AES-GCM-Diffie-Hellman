#include <netdb.h> 
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "Diffie_hellman.h"
#include "aes/aes.h"
#define MAX 256 
#define PORT 8080 
#define SA struct sockaddr 

#define DEBUF 
// Function designed for chat between client and man-in-middle. 

void send_msg(int sockfd, char * buff, int content_length,unsigned char *key){
	//add(16)+iv(12)+tag(16)+data
	unsigned char * crypt_buf=(unsigned char*)malloc(content_length+44);
	memset(crypt_buf,0,content_length+44);
	//add+iv
	unsigned char iv[12],add[16],tag[16];
	memset(tag,0,16);
	for(int j=0;j<16;j++)
		add[j]=rand()%256;
	for(int j=0;j<12;j++)
		iv[j]=rand()%256;
	int tmp=aes_gcm_ae(key, 32,iv,12,buff,content_length,add, 16,crypt_buf+44, tag);
	memcpy(crypt_buf,add,16);
	memcpy(crypt_buf+16,iv,12);
	memcpy(crypt_buf+28,tag,16);
	write(sockfd, crypt_buf, content_length+44);
}
void recv_msg(int sockfd, char * plain_buff,unsigned char *key){
	char buff[MAX];
	//add(16)+iv(12)+tag(16)+data
	unsigned char iv[12],add[16],tag[16];
	int l=read(sockfd, buff, sizeof(buff));
	memcpy(add,buff,16);
	memcpy(iv,buff+16,12);
	memset(tag,0,16);
	int tmp=aes_gcm_ad(key, 32,iv, 12,buff+44, l-44,add, 16,tag, plain_buff);
}
void Mim_key_exchange_server(int c_sockfd,int s_sockfd,unsigned char* aes_key_c, unsigned char* aes_key_s){
	Mim_key mk;
	char buff[MAX];
    init_numbers(&mk);
	
    mk.urand = fopen("/dev/urandom","r");
    if(NULL == mk.urand)
    {
        fprintf(stderr, "Failed to init randomization\n");
        exit(1);
    }
    init_prime(32,&mk);
	//receive prime
	bzero(buff,sizeof(buff));
	read(s_sockfd,buff,sizeof(buff));
    mpz_set_str(mk.prime,buff,16);
	//send prime to client
	write(c_sockfd,buff,sizeof(buff));
	//receive A
	bzero(buff,sizeof(buff));
	read(c_sockfd,buff,sizeof(buff));
	mpz_t key_from_c;
	mpz_init(key_from_c);
	mpz_set_str(key_from_c,buff,16);
	//genarate private key t
    generate_key(32, &mk);
	//T=g^t(mod p)
    mpz_powm(mk.public_key, mk.base, mk.private_key, mk.prime);
	//send T to client
	bzero(buff,MAX);
	mpz_get_str(buff,16,mk.public_key);
	write(c_sockfd, buff, sizeof(buff));
	//send T to server
	write(s_sockfd, buff, sizeof(buff));
	//calc s=g^(at)
    mpz_powm(mk.key_for_client, key_from_c, mk.private_key, mk.prime);
    mpz_get_str(buff,16,mk.key_for_client);
    memcpy(aes_key_c,str2hex(buff),32);
	//receive B
	bzero(buff,MAX);
	read(s_sockfd,buff,sizeof(buff));
	mpz_t key_from_s;
	mpz_init(key_from_s);
	mpz_set_str(key_from_s,buff,16);
	//calc s=g^(bt)
    mpz_powm(mk.key_for_server, key_from_s, mk.private_key, mk.prime);
	//key -> char*
	bzero(buff,MAX);
	mpz_get_str(buff,16,mk.key_for_server);
	memcpy(aes_key_s,str2hex(buff),32);

	fclose(mk.urand);
    clear_numbers(&mk);
}
int connect_server(char *server_ip, char *server_port){
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
	servaddr.sin_addr.s_addr = inet_addr(server_ip);
	servaddr.sin_port = htons(atoi(server_port));

	// connect the client socket to server socket
	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
		printf("connection with the server failed...\n");
		exit(0);
	}
	else
		printf("connected to the server..\n");
	return sockfd;
}
void func(int sockfd_for_client,char *server_ip,char *server_port) 
{
	char buff[MAX]; 
	//connect server
	int sockfd_for_server=0;
	sockfd_for_server=connect_server(server_ip, server_port);
	int n;
	char aes_key_client[32], aes_key_server[32];
	// negotiate key for aes 256
	Mim_key_exchange_server(sockfd_for_client,sockfd_for_server,aes_key_client,aes_key_server);
	puts("server:");
	put_hex(aes_key_server,32);
	puts("client:");
	put_hex(aes_key_client,32);
	for (;;) { 
		bzero(buff, sizeof(buff));
		// read the message from client and copy it in buffer 
		recv_msg(sockfd_for_client, buff, aes_key_client); 
		send_msg(sockfd_for_server, buff, strlen(buff),aes_key_server); 
		// print buffer which contains the client contents 
		printf("From client: %s", buff);
		bzero(buff, sizeof(buff)); 
		recv_msg(sockfd_for_server, buff, aes_key_server);
		send_msg(sockfd_for_client, buff, strlen(buff),aes_key_client); 
		printf("From server: %s", buff);
		// copy server message in the buffer 
	}
} 

// Driver function 
int main(int argc, char **argv) 
{
	if(argc!=4){
		puts("./man-in-middle local_port server_ip server_port");
		return 0;
	}
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
	servaddr.sin_port = htons(atoi(argv[1])); 

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
		printf("man-in-middle listening..\n"); 
	len = sizeof(cli); 

	// Accept the data packet from client and verification 
	connfd = accept(sockfd, (SA*)&cli, &len); 
	if (connfd < 0) { 
		printf("man-in-middle acccept failed...\n"); 
		exit(0); 
	} 
	else
		printf("man-in-middle acccept the client...\n"); 

	// Function for chatting between client and man-in-middle 
	func(connfd,argv[2],argv[3]); 

	// After chatting close the socket 
	close(sockfd); 
} 

