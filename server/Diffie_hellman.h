#include <gmp.h>
#include <string.h>
typedef struct{
	mpz_t prime;
	mpz_t base;
	mpz_t private_key;
	mpz_t public_key;
	mpz_t key;	//g^(AB)
	FILE *urand;
}Dh_key;
void init_numbers(Dh_key* dhk);
void clear_numbers(Dh_key* dhk);
void init_prime(size_t sz,Dh_key* dhk);
void generate_key(size_t sz,Dh_key* dhk);
unsigned char* str2hex(char *hexStr);
void put_hex(unsigned char* value, unsigned int len);
