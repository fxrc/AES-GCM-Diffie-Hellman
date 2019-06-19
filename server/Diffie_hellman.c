#include <stdio.h>
#include "Diffie_hellman.h"
#include <stdlib.h>
#include <time.h>
void generate_random(size_t sz, unsigned char* random_bytes,Dh_key* dhk)
{
    unsigned int init_random = 0;
    size_t i = 0;

    if(0 == sz || NULL == random_bytes)
    {
        fprintf(stderr, "Wrong params for generate_random()\n");
        exit(1);
    }
    init_random ^= ((unsigned int)fgetc(dhk->urand) << 8)|fgetc(dhk->urand);
    srand(init_random);
    for(i = 0; i < sz; i++)
    {
        random_bytes[i] =  rand();
    }
}

void put_hex(unsigned char* value, unsigned int len){
    for(int i=0;i<len;i++)
        printf("%02x",value[i]);
    puts("");
}
char* str2hex(char *hexStr){
    int len=strlen(hexStr)/2;
    unsigned char * hexvalue=(unsigned char*)malloc(len*sizeof(char));
    memset(hexvalue,0,len);
    for(int i=0;i<len;i++){
        if(hexStr[i*2]<='9'){
            hexvalue[i]=(hexStr[i*2]-'0')*16;
        }else
            hexvalue[i]=(hexStr[i*2]-87)*16;   //a的码是97

        if(hexStr[i*2+1]<='9'){
            hexvalue[i]+=(hexStr[i*2+1]-'0');
        }else
            hexvalue[i]+=(hexStr[i*2+1]-87);
    }
    return hexvalue;
}

void generate_key(size_t sz, Dh_key* dhk)
{
    unsigned char* random_bytes = NULL;

    if(0 == sz || NULL == dhk->private_key)
    {
        fprintf(stderr, "Wrong params for generate_key()\n");
        exit(1);
    }
    random_bytes = (unsigned char *)malloc(sz*sizeof(unsigned char));
    if(NULL == random_bytes)
    {
        fprintf(stderr, "Failed to allocate random bytes array for the private key\n");
        exit(1);
    }
    generate_random(sz, random_bytes, dhk);
    mpz_import(dhk->private_key, 1, -1, sz, -1, 0, (const void*)random_bytes);
    free(random_bytes);
}


void init_prime(size_t sz,Dh_key* dhk)
{
    mpz_t tmp;
    mpz_t x;
    unsigned char* random_bytes = NULL;


    if(0 == sz)
    {
        fprintf(stderr, "Wrong params for init_prime()\n");
        exit(1);
    }

    mpz_init(tmp);
    mpz_init(x);

    random_bytes = (unsigned char *)malloc(sz*sizeof(unsigned char));
    if(NULL == random_bytes)
    {
        fprintf(stderr, "Failed to allocate random bytes array for the prime number\n");
        exit(1);
    }
    while (1)
    {
        generate_random(sz, random_bytes,dhk);
        random_bytes[sz-1] |= (unsigned char)0x40;
        random_bytes[0] |= (unsigned char)1;

        mpz_import(tmp, 1, -1, sz, -1, 0, (const void*)random_bytes);
        while (0 == mpz_probab_prime_p(tmp, 10))
        {
            mpz_add_ui(tmp, tmp, 2);
        }
        mpz_mul_ui(dhk->prime, tmp, 2);
        mpz_add_ui(dhk->prime, dhk->prime, 1);
        if (0 != mpz_probab_prime_p(dhk->prime, 10))
        {
            break;
        }
    }
    free(random_bytes);

    mpz_set_ui(dhk->base, (unsigned long)2);

    mpz_clear(tmp);
    mpz_clear(x);
}



void init_numbers(Dh_key* dhk)
{
    mpz_init(dhk->key);
    mpz_init(dhk->prime);
    mpz_init(dhk->base);
    mpz_init(dhk->private_key);
    mpz_init(dhk->public_key);
}

void clear_numbers(Dh_key* dhk)
{
    mpz_clear(dhk->key);
    mpz_clear(dhk->prime);
    mpz_clear(dhk->base);
    mpz_clear(dhk->private_key);
    mpz_clear(dhk->public_key);
}
