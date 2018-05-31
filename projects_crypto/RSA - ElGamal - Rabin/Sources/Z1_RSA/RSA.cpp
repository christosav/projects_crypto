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

#define PRIMELENGTH    512  //Bits size of primes p and q

struct RSAPublicKey
{
    mpz_t e;  // Public Exponent
    mpz_t N;  // Modulus
    ~RSAPublicKey()
    {
        mpz_clear(e);
        mpz_clear(N);
    }
} ;


struct RSAPrivateKey
{
    mpz_t d; // Private Exponent
    mpz_t N; // Modulus
    ~RSAPrivateKey()
    {
        mpz_clear(d);
        mpz_clear(N);

    }
} ;

struct RSAKeyPair
{
    RSAPublicKey* pk;
    RSAPrivateKey* sk;

} ;


class RSAEncryption
{
private:
    gmp_randstate_t r_state;
    void initMPZ();
    string encode(const string &);
    string decode(const string &);
public:
    RSAEncryption()
    {
        initMPZ();
    }
    ~RSAEncryption()
    {
        gmp_randclear(r_state);
    }
    void (*mpz_clear_func)(void *, size_t);
    void printMPZnumber(mpz_t);
    RSAKeyPair* generateKeyPair(int);
    void printKeyPair(const RSAKeyPair);
    string encrypt(string,const RSAPublicKey*);
    string decrypt(string,const RSAPrivateKey*);
};

int main(void)
{

    RSAEncryption RSA;

    cout << "Asymmetric Encryption with RSA Algorithm using GMP " << gmp_version << endl;



    cout << "******** BEGIN RSA KeyPair Generation ********" << endl << endl;

    RSAKeyPair* keypair = RSA.generateKeyPair(PRIMELENGTH);

    cout << "******** END RSA KeyPair Generation ********" << endl << endl<< endl;

    RSA.printKeyPair(*keypair);




    cout  << endl<<"********  BEGIN RSA Public-Key Encryption ********" << endl << endl;

    string encrypted(RSA.encrypt("This is my secret!",keypair->pk));

    cout << "********  END Public-Key Encryption ********" << endl << endl;



    cout  << endl<<"********  BEGIN RSA Private-Key Decryption ********" << endl << endl;

    string decrypted(RSA.decrypt(encrypted,keypair->sk));

    cout << "********  END Private-Key Decryption ********" << endl << endl;


    return EXIT_SUCCESS;
}

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
    cout << num_str;
    mpz_clear_func(num_str, strlen(num_str) + 1);
}

//Generation of a random RSA keypair
RSAKeyPair* RSAEncryption::generateKeyPair(int primelength)
{
    ///Step 1 : Generation of two random large primes (p and q).
    cout << "\t 1. Random Primes Generation" << endl << endl;

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

    cout << "Random Prime 'p' = ";
    printMPZnumber(p);
    cout << " | Propably Prime: "  << (mpz_probab_prime_p(p, 10)!=0?"true":"false") << " | Size: " << mpz_sizeinbase(p, 2) << " bits" << endl<< endl;
    cout << "Random Prime 'q' = " ;
    printMPZnumber(q);
    cout << " | Propably Prime: "  << (mpz_probab_prime_p(q, 10)!=0?"true":"false") << " | Size: " << mpz_sizeinbase(q, 2)  << " bits"<< endl<< endl;

    ///Step 2 : Computation of modulus N = pq
    ///and x = (p-1)(q-1).
    cout << "\t 2. Computation of Modulus N = pq and and x = (p-1)(q-1)" << endl << endl;

    mpz_t N,x;

    mpz_init(N);
    mpz_init(x);

    mpz_mul(N,p,q);

    cout << "Computed 'N' = " ;
    printMPZnumber(N);
    cout << " | Propably Prime: "  << (mpz_probab_prime_p(N, 10)!=0?"true":"false") << " | Size: " << mpz_sizeinbase(N, 2) << " bits" << endl<< endl;


    ///Computation of x = (p-1)(q-1)

    mpz_t p_minus_1,q_minus_1;

    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1,p,1);
    mpz_sub_ui(q_minus_1,q,1);

    mpz_mul(x,p_minus_1,q_minus_1);


    ///Step 3 : Generation of a random small odd integer e such that gcd(e,x) = 1.
    cout << "\t 3. Generation of odd integer e where gcd(e,x)=1 " << endl << endl;

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

    cout << "'e' = " ;
    printMPZnumber(e);
    cout << " | Size: " << mpz_sizeinbase(e, 2) << endl<< endl;


    ///Step 4 : Computation of the unique d such that ed = 1(mod x)
    cout << "\t 4. Computation of the unique d where ed = 1(mod x) " << endl << endl;

    mpz_t d;
    mpz_init(d);

    if(mpz_invert(d,e,x)==0 || d == 0)
    {
        cerr << "Could not find multiplicative inverse!" << endl;
        cout << "Trying again..."<< endl<< endl;
        generateKeyPair(primelength);
    }

    cout << "'d' = " ;
    printMPZnumber(d);
    cout << " | Size: " << mpz_sizeinbase(d, 2) << endl<< endl;

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
    cout << "------------- RSA Keypair -------------" << endl;
    cout << "RSA Public Key (N,e): " ;
    printMPZnumber(kpair.pk->N);
    printMPZnumber(kpair.pk->e);
    cout << endl << "\t\t-----------------------" << endl;
    cout << "RSA Private Key (N,d): " ;
    printMPZnumber(kpair.sk->N);
    printMPZnumber(kpair.sk->d);
    cout << endl << "---------------------------------------------------------" << endl<< endl;
}

//Encodes a string to integer format
string RSAEncryption::encode(const string& s)
{
    ostringstream pad;

    for (int i = 0; i < s.length(); i++)
    {
        int ascii = (int)s[i]+666-(int)s[i+1];
        pad << ascii;
    }
    return pad.str();
}

//Decodes a string from integer format
string RSAEncryption::decode(const string& s)
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

string RSAEncryption::encrypt(string plaintext,const RSAPublicKey *key)
{

    cout << "\t 1. Integer Representation of Message "<<endl<<endl;
    cout << "Plain Text: " << plaintext << endl;

    string encoded = encode(plaintext);
    cout << "Encoded Plain Text: " << encoded << endl<<endl;

    cout << "\t 2. Computation of c = m^e mod n "<<endl<<endl;

    mpz_t et, ct;
    mpz_init(ct);
    mpz_init(et);

    mpz_set_str(et,encoded.c_str(),10);

    ///Repeated square-and-multiply algorithm
    mpz_powm_sec(ct, et, key->e, key->N);

    char* ciphertext = mpz_get_str(NULL,10,ct);

    cout << "Cipher Text: " <<ciphertext << endl<< endl;

    mpz_clear(et);
    mpz_clear(ct);

    return string(ciphertext);
}

string RSAEncryption::decrypt(string ciphertext,const RSAPrivateKey *key)
{
    cout << "Cipher Text: " <<ciphertext << endl<< endl;
    cout << "\t 1. Computation of m = c^d mod n. "<<endl<<endl;

    mpz_t ct, et;
    mpz_init(ct);
    mpz_init(et);

    mpz_set_str(ct,ciphertext.c_str(),10);

    ///Repeated square-and-multiply algorithm
    mpz_powm_sec(et, ct, key->d, key->N);

    char* encoded = mpz_get_str(NULL,10,et);
    cout << "Encoded Plain Text: " <<encoded << endl<< endl;


    string plaintext = decode(string(encoded));

    cout << "\t 2. String Representation of Message "<<endl;
    cout << "Plain Text: " << plaintext << endl << endl;

    mpz_clear(ct);
    mpz_clear(et);

    return plaintext;
}
