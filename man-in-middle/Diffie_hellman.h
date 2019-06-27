#include <gmp.h>
#include <string.h>
typedef struct{
	mpz_t prime;
	mpz_t base;
	mpz_t private_key;
	mpz_t public_key;
	mpz_t key_for_server;	//g^(AB)	
	mpz_t key_for_client;	//g^(AB)
	FILE *urand;
}Mim_key;
void init_numbers(Mim_key* dhk);
void clear_numbers(Mim_key* dhk);
void init_prime(size_t sz,Mim_key* dhk);
void generate_key(size_t sz,Mim_key* dhk);
unsigned char* str2hex(char *hexStr);
void put_hex(unsigned char* value, unsigned int len);
