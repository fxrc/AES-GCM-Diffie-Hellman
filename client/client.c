#include <memory.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "Diffie_hellman.h"
#include "aes/aes.h"
#include <unistd.h>


#define AES_DEBUG
#define MAX 256
#define PORT 8080
#define SA struct sockaddr

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
void DH_key_exchange_client(int sockfd,unsigned char * key_aes){
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
	generate_key(32, &client_key);
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
	//key -> char*
	bzero(buff,MAX);
	mpz_get_str(buff,16,client_key.key);
	memcpy(key_aes,str2hex(buff),32);
	fclose(client_key.urand);
	clear_numbers(&client_key);
}
void func(int sockfd)
{	
	//connect to server
	char buff[MAX];
	int n=0;
	unsigned char aes_key[32];
	//negotiate a 256bit key for aes
	DH_key_exchange_client(sockfd,aes_key);
	put_hex(aes_key, 32);
	//chatting..
	for (;;) {
		bzero(buff, sizeof(buff));
		printf("Enter the string : ");
		n = 0;
		while ((buff[n++] = getchar()) != '\n')
			;
		send_msg(sockfd, buff, strlen(buff),aes_key);
		bzero(buff, sizeof(buff));
		recv_msg(sockfd, buff, aes_key);
		printf("From Server : %s", buff);
		if ((strncmp(buff, "exit", 4)) == 0) {
			printf("Client Exit...\n");
			break;
		}
	}
}

int main(int argc,char **argv)
{
	if(argc!=3){
		puts("./client ip port");
		return 0;
	}
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
	servaddr.sin_addr.s_addr = inet_addr(argv[1]);
	servaddr.sin_port = htons(atoi(argv[2]));

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
