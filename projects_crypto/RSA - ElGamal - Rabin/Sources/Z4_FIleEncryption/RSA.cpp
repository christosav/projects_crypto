#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include "RSA.h"

void RSAEncryption::initMPZ()
{
    //Clear Function
    mp_get_memory_functions (NULL, NULL, &mpz_clear_func);

    //Initialize rand seed
    unsigned long int seed = (unsigned) time(NULL);

    //initialize r_state and set seed
    gmp_randinit_default (r_state);
    gmp_randseed_ui(r_state, seed);
}

//Prints an mpz_t number on console
void RSAEncryption::printMPZnumber(mpz_t num)
{
    char* num_str = mpz_get_str(NULL,10,num);
    std::cout << num_str;
    mpz_clear_func(num_str, strlen(num_str) + 1);
}

//Generation of a random RSA keypair
RSAKeyPair* RSAEncryption::generateKeyPair(int primelength)
{
    ///Step 1 : Generation of two random large primes (p and q).
    mpz_t p, q;

    mpz_init(p);
    mpz_init(q);

    do
    { mpz_urandomb(p,r_state,primelength);
        mpz_nextprime(p,p);
    }
    while(mpz_sizeinbase(p, 2)!=primelength);

    do
    { mpz_urandomb(q,r_state,primelength);
        mpz_nextprime(q,q);
    }
    while(mpz_sizeinbase(q, 2)!=primelength);

    ///Step 2 : Computation of modulus N = pq
    ///and x = (p-1)(q-1).

    mpz_t N,x;

    mpz_init(N);
    mpz_init(x);

    mpz_mul(N,p,q);

    ///Computation of x = (p-1)(q-1)

    mpz_t p_minus_1,q_minus_1;

    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1,p,1);
    mpz_sub_ui(q_minus_1,q,1);

    mpz_mul(x,p_minus_1,q_minus_1);


    ///Step 3 : Generation of a random small odd integer e such that gcd(e,x) = 1.

    mpz_t e,gcd;
    mpz_init(e);
    mpz_init(gcd);

    int e_int  = (65537 + (2 * (rand() % 15)));

    do
    {
        mpz_gcd_ui(gcd,x,e_int);

        //try the next odd integer...
        e_int += 2;
    }
    while(mpz_cmp_ui(gcd,1)!=0);

    mpz_set_ui(e,e_int);


    ///Step 4 : Computation of the unique d such that ed = 1(mod x)
    mpz_t d;
    mpz_init(d);

    if(mpz_invert(d,e,x)==0 || d == 0)
    {
        generateKeyPair(primelength);
    }

    ///Keys Generated!

    RSAKeyPair* kpair = new RSAKeyPair();

    kpair->pk = new RSAPublicKey();
    kpair->sk = new RSAPrivateKey();

    mpz_set(kpair->pk->N, N);
    mpz_set(kpair->pk->e, e);

    mpz_set(kpair->sk->N, N);
    mpz_set(kpair->sk->d, d);

    //clear
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(N);
    mpz_clear(x);
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(e);
    mpz_clear(gcd);
    mpz_clear(d);

    return kpair;
}

//Prints an RSA keypair on console
void RSAEncryption::printKeyPair(const RSAKeyPair kpair)
{
    std::cout << "------------- RSA Keypair -------------" << std::endl;
    std::cout << "RSA Public Key (N,e): " ;
    printMPZnumber(kpair.pk->N);
    printMPZnumber(kpair.pk->e);
    std::cout << std::endl << "\t\t-----------------------" << std::endl;
    std::cout << "RSA Private Key (N,d): " ;
    printMPZnumber(kpair.sk->N);
    printMPZnumber(kpair.sk->d);
    std::cout << std::endl << "---------------------------------------------------------" << std::endl<< std::endl;
}

//Encodes a std::string to integer format
std::string RSAEncryption::encode(const std::string& s)
{
    std::ostringstream pad;

    for (int i = 0; i < s.length(); i++)
    {
        int ascii = (int)s[i]+666-(int)s[i+1];
        pad << ascii;
    }
    return pad.str();
}

//Decodes a std::string from integer format
std::string RSAEncryption::decode(const std::string& s)
{
    std::ostringstream pad;
    std::string temp;
    int ascii = 0;
    for (int i = s.length()-1; i>0; i-=3)
    {
        temp += s[i-2] ;
        temp += s[i-1];
        temp += s[i];

        ascii = ((int)atoi(temp.c_str()))-666 + ascii;

        pad << (char)ascii;
        temp = "";
    }
    temp = pad.str();
    reverse(temp.begin(),temp.end());
    return temp;
}

std::string RSAEncryption::encrypt(std::string plaintext,const RSAPublicKey key)
{

    std::string encoded = encode(plaintext);

    mpz_t et, ct;
    mpz_init(ct);
    mpz_init(et);

    mpz_set_str(et,encoded.c_str(),10);

    ///Repeated square-and-multiply algorithm
    mpz_powm_sec(ct, et, key.e, key.N);

    char* ciphertext = mpz_get_str(NULL,10,ct);

    mpz_clear(et);
    mpz_clear(ct);

    return std::string(ciphertext);
}

std::string RSAEncryption::decrypt(std::string ciphertext,const RSAPrivateKey key)
{
    mpz_t ct, et;
    mpz_init(ct);
    mpz_init(et);

    mpz_set_str(ct,ciphertext.c_str(),10);

    ///Repeated square-and-multiply algorithm
    mpz_powm_sec(et, ct, key.d, key.N);

    char* encoded = mpz_get_str(NULL,10,et);

    std::string plaintext = decode(std::string(encoded));

    mpz_clear(ct);
    mpz_clear(et);

    return plaintext;
}
