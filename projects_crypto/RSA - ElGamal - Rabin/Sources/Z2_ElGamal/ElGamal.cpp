#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <gmpxx.h>

using namespace std;


#define PRIMELENGTH    200  /* size of the primes p and q  */

struct ElGamalPublicKey
{
    mpz_t p;
    mpz_t a;
    mpz_t h;
    ~ElGamalPublicKey()
    {
        mpz_clear(p);
        mpz_clear(a);
        mpz_clear(h);
    }
} ;
struct ElGamalPrivateKey
{
    mpz_t p;
    mpz_t q; /* Private Exponent */
    ~ElGamalPrivateKey()
    {
        mpz_clear(p);
        mpz_clear(q);
    }
} ;

struct ElGamalKeyPair
{
    ElGamalPublicKey* pk;
    ElGamalPrivateKey* sk;

} ;


class encryption
{
private:
    gmp_randstate_t r_state;
    void initMPZ();
    string encode(const string &);
    string decode(const string &);
    long SMA( long,  long,  long );
public:
    encryption()
    {
        initMPZ();
    }
    ~encryption()
    {
        gmp_randclear(r_state);
    }
    void (*mpz_clear_func)(void *, size_t);
    void printMPZnumber(mpz_t);
    ElGamalKeyPair* generateKeyPair(int);
    void printKeyPair(ElGamalKeyPair);
    string encrypt(string,ElGamalPublicKey*);
    string decrypt(string,ElGamalPrivateKey*);
};

int main(void)
{

    encryption ElGamal;

    cout << "Asymmetric Encryption with ElGamal Algorithm using GMP " << gmp_version << endl;


    cout << "******** BEGIN ElGamal KeyPair Generation ********" << endl << endl;

    ElGamalKeyPair* keypair = ElGamal.generateKeyPair(PRIMELENGTH);

    cout << "******** END ElGamal KeyPair Generation ********" << endl << endl<< endl;

    ElGamal.printKeyPair(*keypair);



    cout  << endl<<"********  BEGIN ElGamal Public-Key Encryption ********" << endl << endl;

    string encrypted(ElGamal.encrypt("This is my secret!",keypair->pk));

    cout << "********  END Public-Key Encryption ********" << endl << endl;


    cout  << endl<<"********  BEGIN ElGamal Private-Key Decryption ********" << endl << endl;

    string decrypted(ElGamal.decrypt(encrypted,keypair->sk));

    cout << "********  END Private-Key Decryption ********" << endl << endl;


    return EXIT_SUCCESS;
}

void encryption::initMPZ()
{
    mp_get_memory_functions (NULL, NULL, &mpz_clear_func);

    unsigned long int seed = (unsigned) time(NULL);

    gmp_randinit_default (r_state);
    gmp_randseed_ui(r_state, seed);
}

void encryption::printMPZnumber(mpz_t num)
{
    char* num_str = mpz_get_str(NULL,10,num);
    cout << num_str;
    mpz_clear_func(num_str, strlen(num_str) + 1);
}

ElGamalKeyPair* encryption::generateKeyPair(int primelength)
{

    mpz_t p,a,q,h;

    mpz_init(p);
    mpz_init(a);
    mpz_init(q);
    mpz_init(h);

    ///p is a large prime
    cout << "\t 1. Random Prime Generation" << endl << endl;
    do
    {
        mpz_urandomb(p,r_state,primelength);
        mpz_nextprime(p,p);
    }
    while(mpz_sizeinbase(p, 2)!=primelength);

     cout << "Random Prime 'p' = ";
    printMPZnumber(p);
    cout << " | Propably Prime: "  << (mpz_probab_prime_p(p, 10)!=0?"true":"false") << " | Size: " << mpz_sizeinbase(p, 2) << " bits" << endl<< endl;

    ///a is the generator
     cout << "\t 2. Generator Selection" << endl << endl;
     do
    {
            mpz_urandomb(a,r_state,primelength);
            mpz_nextprime(a,a);
    }
    while (mpz_cmp(a,p)>=0);

    cout << "Random Generator 'a' = ";
    printMPZnumber(a);
    cout << " | Propably Prime: "  << (mpz_probab_prime_p(a, 10)!=0?"true":"false") << " | Size: " << mpz_sizeinbase(a, 2) << " bits" << endl<< endl;

    ///Get some random q < p
     cout << "\t 3. Random Exponent Generation" << endl << endl;
    do
    {
            mpz_urandomb(q,r_state,primelength);
    }
    while (mpz_cmp(q,p)>=0);

    cout << "Random Integer 'q' = ";
    printMPZnumber(q);
    cout << " | Size: " << mpz_sizeinbase(q, 2) << " bits" << endl<< endl;

    ///h = a^q (mod p)
    cout << "\t 4. Computation of h = a^q (mod p)" << endl << endl;

    mpz_powm_sec(h,a,q,p);

    cout << "'h' = ";
    printMPZnumber(h);
    cout << " | Size: " << mpz_sizeinbase(h, 2) << " bits" << endl<< endl;

    ///Keys Generated!

    ElGamalKeyPair* kpair = new ElGamalKeyPair();

    kpair->pk = new ElGamalPublicKey();
    kpair->sk = new ElGamalPrivateKey();

    mpz_set(kpair->pk->p, p);
    mpz_set(kpair->pk->a, a);
    mpz_set(kpair->pk->h, h);

    mpz_set(kpair->sk->p, p);
    mpz_set(kpair->sk->q, q);

    mpz_clear(p);
    mpz_clear(a);
    mpz_clear(q);
    mpz_clear(h);

    return kpair ;
}

void encryption::printKeyPair(ElGamalKeyPair kpair)
{
    cout << "------------- ElGamal Keypair -------------" << endl;
    cout << "ElGamal Public Key (p,a,h): " ;
    printMPZnumber(kpair.pk->p);
    printMPZnumber(kpair.pk->a);
    printMPZnumber(kpair.pk->h);
    cout << endl << "\t\t-----------------------" << endl;
    cout << "ElGamal Private Key (p,q): " ;
    printMPZnumber(kpair.sk->p);
    printMPZnumber(kpair.sk->q);
    cout << endl << "---------------------------------------------------------" << endl<< endl;
}

string encryption::encode(const string& s)
{
    ostringstream pad;

    for (int i = 0; i < s.length(); i++)
    {
        int ascii = (int)s[i]+666-(int)s[i+1];
        pad << ascii;
    }
    return pad.str();
}

string encryption::decode(const string& s)
{
    ostringstream pad;
    string temp;
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

string encryption::encrypt(string plaintext, ElGamalPublicKey *key)
{

    cout << "\t 1. Integer Representation of Message "<<endl<<endl;
    cout << "Plain Text: " << plaintext << endl;

    string encoded = encode(plaintext);
    cout << "Encoded Plain Text: " << encoded << endl<<endl;

    mpz_t k, s;
	mpz_init(k);
	mpz_init(s);

	cout << "\t 1. Random Integer Generation"<<endl<<endl;
	///k < p
	do
    {
        mpz_urandomb(k,r_state,mpz_sizeinbase(key->p,2));
    }
    while(mpz_cmp(k,key->p)>=0);

    cout << "Random Integer 'k' = ";
    printMPZnumber(k);
    cout << " | Size: " << mpz_sizeinbase(k, 2) << " bits" << endl<< endl;

    cout << "\t 2. Computation of h^k (mod p)"<<endl<<endl;

	///s = h^k (mod p)
	mpz_powm_sec(s,key->h,k,key->p);

	 cout << "'s' = ";
    printMPZnumber(s);
    cout << " | Size: " << mpz_sizeinbase(s, 2) << " bits" << endl<< endl;

    mpz_t et, ct1, ct2;
    mpz_init(et);
    mpz_init(ct1);
	mpz_init(ct2);

	mpz_set_str(et,encoded.c_str(),10);

    cout << "\t 3. Computation First Cipher Part"<<endl<<endl;

	///c1 = a^k (mod p)
	mpz_powm_sec(ct1,key->a,k,key->p);

	cout << "'ct1' = g^y (mod p) = ";
    printMPZnumber(ct1);
    cout << " | Size: " << mpz_sizeinbase(ct1, 2) << " bits" << endl<< endl;

    cout << "\t 4. Computation Second Cipher Part"<<endl<<endl;

	///ct2 = m s (mod p)
	mpz_mul(ct2,et,s);
	mpz_mod(ct2,ct2,key->p);

	cout << "'ct2' = m s (mod p) = ";
    printMPZnumber(ct2);
    cout << " | Size: " << mpz_sizeinbase(ct2, 2) << " bits" << endl<< endl;

    char* ciphertext1 = mpz_get_str(NULL,10,ct1);
    char* ciphertext2 = mpz_get_str(NULL,10,ct2);

    string ciphertext;
    int ct1len = strlen(ciphertext1), ct2len = strlen(ciphertext2);
    if(ct1len<ct2len){
        for(int i=0;i<(ct2len-ct1len);i++){
            ciphertext += '0';
        }
    }
    ciphertext += ciphertext1;
    if(ct2len<ct1len){
        for(int i=0;i<(ct1len-ct2len);i++){
            ciphertext += '0';
        }
    }
    ciphertext += ciphertext2;

    cout << "Cipher Text: " << ciphertext << endl<< endl;

    mpz_clear(k);
    mpz_clear(s);
    mpz_clear(et);
    mpz_clear(ct1);
    mpz_clear(ct2);

    return ciphertext;
}


string encryption::decrypt(string ciphertext, ElGamalPrivateKey *key)
{
    cout << "Cipher Text: " << ciphertext << endl<< endl;

    int clen = ciphertext.length();
    string ciphertext1 = ciphertext.substr(0,(clen/2));
    string ciphertext2 = ciphertext.substr((clen/2),clen);

    cout << "First Cipher Part: " << ciphertext1 <<endl;
    cout << "Second Cipher Part: " << ciphertext2 <<endl<<endl;

    mpz_t ct1, ct2;
    mpz_init(ct1);
    mpz_init(ct2);

    mpz_set_str(ct1,ciphertext1.c_str(),10);
    mpz_set_str(ct2,ciphertext2.c_str(),10);

    cout << "\t 1. Computation of s = ct1^q (mod p). "<<endl<<endl;

    mpz_t s;
	mpz_init(s);

    ///s = ct1^q (mod p)
	mpz_powm_sec(s,ct1,key->q,key->p);

	cout << "'s' = ";
    printMPZnumber(s);
    cout << " | Size: " << mpz_sizeinbase(s, 2) << " bits" << endl<< endl;


    cout << "\t 2. Computation of s_inv = s^(-1). "<<endl<<endl;

	mpz_t s_inv;
	mpz_init(s_inv);

	///s_inv = s^(-1)
	mpz_invert(s_inv,s,key->p);

	cout << "'s_inv' = ";
    printMPZnumber(s_inv);
    cout << " | Size: " << mpz_sizeinbase(s_inv, 2) << " bits" << endl<< endl;


    cout << "\t 3. Computation of m = ct2 s_inv (mod p). "<<endl<<endl;

	mpz_t et;
	mpz_init(et);

	///m = ct2 s_inv (mod p)
	mpz_mul(et,ct2,s_inv);
    mpz_mod(et,et,key->p);

    char* encoded = mpz_get_str(NULL,10,et);
    cout << "Encoded Plain Text: " << encoded << endl<< endl;


    string plaintext = decode(string(encoded));

    cout << "\t 2. String Representation of Message "<<endl;
    cout << "Plain Text: " << plaintext << endl << endl;

    mpz_clear(s);
    mpz_clear(s_inv);
    mpz_clear(ct1);
    mpz_clear(ct2);
    mpz_clear(et);

    return plaintext;
}
