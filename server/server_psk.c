#include <netdb.h> 
#include <netinet/in.h> 
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
// Function designed for chat between client and server. 

void send_msg(int sockfd, char * buff, int content_length,unsigned char *key){
	//add(16)+iv(12)+tag(16)+data
	unsigned char * crypt_buf=(unsigned char*)malloc(content_length+44+4);
	memset(crypt_buf,0,content_length+44+4);
	//add+iv
	unsigned char iv[12],add[16],tag[16];
	memset(tag,0,16);
	for(int j=0;j<16;j++)
		add[j]=rand()%256;
	for(int j=0;j<12;j++)
		iv[j]=rand()%256;
	int tmp=aes_gcm_ae(key, 32,iv,12,buff,content_length,add, 16,crypt_buf+44+4, tag);
	memcpy(crypt_buf,"data",4);
	memcpy(crypt_buf+4,add,16);
	memcpy(crypt_buf+20,iv,12);
	memcpy(crypt_buf+32,tag,16);
	write(sockfd, crypt_buf, content_length+44+4);
}
void recv_msg(int sockfd, char * plain_buff,unsigned char *key){
	char buff[MAX];
	//add(16)+iv(12)+tag(16)+data
	unsigned char iv[12],add[16],tag[16];
	int l=read(sockfd, buff, sizeof(buff));
	memcpy(add,buff+4,16);
	memcpy(iv,buff+16+4,12);
	memset(tag,0,16);
	int tmp=aes_gcm_ad(key, 32,iv, 12,buff+44+4, l-44-4,add, 16,tag, plain_buff);
}
void server_key_exchange_server(int sockfd,unsigned char* aes_key){
	//psk
	mpz_t passwd;
	mpz_init(passwd);
	mpz_import(passwd, 1, -1, sizeof("password"), -1, 0, (const void*)"password");
	Dh_key server_key;
	char buff[MAX];
    init_numbers(&server_key);

    server_key.urand = fopen("/dev/urandom","r");
    if(NULL == server_key.urand)
    {
        fprintf(stderr, "Failed to init randomization\n");
        exit(1);
    }
    init_prime(32,&server_key);
	//send prime
	bzero(buff,MAX);
	memcpy(buff,"pri",3);
	mpz_get_str(buff+3,16,server_key.prime);
	write(sockfd,buff,sizeof(buff));

	//receive A'
	bzero(buff,MAX);
	read(sockfd,buff,sizeof(buff));
	mpz_t key_from_c;
	mpz_init(key_from_c);
	mpz_set_str(key_from_c,buff+3,16);
	mpz_invert(key_from_c, key_from_c, server_key.prime);
	//calculate private key b 
    generate_key(32, &server_key);
	mpz_mul(server_key.private_key, server_key.private_key, passwd);
	//B'=g^(bQ)(mod p)
    mpz_powm(server_key.public_key, server_key.base, server_key.private_key, server_key.prime);
	//send B'
	bzero(buff,MAX);
	memcpy(buff,"pub",3);
	mpz_get_str(buff+3,16,server_key.public_key);
	write(sockfd, buff, sizeof(buff));
	//calc s=g^(ab)
    mpz_powm(server_key.key, key_from_c, server_key.private_key, server_key.prime);
    mpz_get_str(buff,16,server_key.key);
    memcpy(aes_key,str2hex(buff),32);
	fclose(server_key.urand);
    clear_numbers(&server_key);
}

void func(int sockfd) 
{ 
	char buff[MAX]; 
	int n; 
	char aes_key[32];
	// negotiate key for aes 256
	server_key_exchange_server(sockfd,aes_key);
	put_hex(aes_key,32);
	for (;;) { 
		bzero(buff, sizeof(buff)); 
		// read the message from client and copy it in buffer 
		recv_msg(sockfd, buff, aes_key); 
		// print buffer which contains the client contents 
		printf("From client: %sTo client : ", buff); 
		bzero(buff, sizeof(buff)); 
		n = 0; 
		// copy server message in the buffer 
		while ((buff[n++] = getchar()) != '\n');
		// and send that buffer to client 
		send_msg(sockfd, buff, strlen(buff),aes_key); 
		// if msg contains "Exit" then server exit and chat ended. 
		if (strncmp("exit", buff, 4) == 0) { 
			printf("Server Exit...\n"); 
			break; 
		} 
	}
} 

// Driver function 
int main(int argc, char **argv) 
{
	if(argc!=2){
		puts("./server port");
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

