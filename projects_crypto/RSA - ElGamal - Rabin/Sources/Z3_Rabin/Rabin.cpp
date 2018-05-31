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

struct RabinPublicKey
{
    mpz_t n;
    ~RabinPublicKey()
    {
        mpz_clear(n);
    }
} ;
struct RabinPrivateKey
{
    mpz_t p;
    mpz_t q;
    mpz_t n;
    ~RabinPrivateKey()
    {
        mpz_clear(p);
        mpz_clear(q);
        mpz_clear(n);
    }
} ;

struct RabinKeyPair
{
    RabinPublicKey* pk;
    RabinPrivateKey* sk;

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
    RabinKeyPair* generateKeyPair(int);
    void printKeyPair(RabinKeyPair);
    string encrypt(string,RabinPublicKey*);
    void findSqrtsModPrime(mpz_t, mpz_t, mpz_t);
    string decrypt(string,RabinPrivateKey*);
};

int main(void)
{

    encryption Rabin;

    cout << "Asymmetric Encryption with Rabin Algorithm using GMP" << gmp_version << endl;


    cout << "******** BEGIN Rabin KeyPair Generation ********" << endl << endl;

    RabinKeyPair* keypair = Rabin.generateKeyPair(PRIMELENGTH);

    cout << "******** END Rabin KeyPair Generation ********" << endl << endl<< endl;

    Rabin.printKeyPair(*keypair);



    cout  << endl<<"********  BEGIN Rabin Public-Key Encryption ********" << endl << endl;

    string encrypted(Rabin.encrypt("This is my secret!",keypair->pk));

    cout << "********  END Public-Key Encryption ********" << endl << endl;


    cout  << endl<<"********  BEGIN Rabin Private-Key Decryption ********" << endl << endl;

    string decrypted(Rabin.decrypt(encrypted,keypair->sk));

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

RabinKeyPair* encryption::generateKeyPair(int primelength)
{

    ///1 : Generation of two random large primes (p and q) equivalent to 3mod4.
    cout << "\t 1. Random Primes Generation" << endl << endl;

    mpz_t p, q, temp;

    mpz_init(p);
    mpz_init(q);
    mpz_init(temp);

    do
    {
        mpz_urandomb(p,r_state,primelength);
        mpz_nextprime(p,p);
        mpz_mod_ui(temp,p,4);
    }
    while(mpz_sizeinbase(p, 2)!=primelength || mpz_cmp_ui(temp,3)!=0);

    do
    {
        mpz_urandomb(q,r_state,primelength);
        mpz_nextprime(q,q);
        mpz_mod_ui(temp,q,4);
    }
    while(mpz_sizeinbase(q, 2)!=primelength || mpz_cmp_ui(temp,3)!=0);

    cout << "Random Prime 'p' = ";
    printMPZnumber(p);
    cout << " | Propably Prime: "  << (mpz_probab_prime_p(p, 10)!=0?"true":"false") << " | Size: " << mpz_sizeinbase(p, 2) << " bits" << endl<< endl;
    cout << "Random Prime 'a' = " ;
    printMPZnumber(q);
    cout << " | Propably Prime: "  << (mpz_probab_prime_p(q, 10)!=0?"true":"false") << " | Size: " << mpz_sizeinbase(q, 2)  << " bits"<< endl<< endl;

    ///2 : Computation of n = pq.
    cout << "\t 2. Computation of n = pq" << endl << endl;

    mpz_t n;
    mpz_init(n);

    mpz_mul(n,p,q);

    cout << "'n' = " ;
    printMPZnumber(n);
    cout << " | Size: " << mpz_sizeinbase(n, 2) << endl<< endl;

    ///Keys Generated!

    RabinKeyPair* kpair = new RabinKeyPair();

    kpair->pk = new RabinPublicKey();
    kpair->sk = new RabinPrivateKey();

    mpz_set(kpair->pk->n, n);

    mpz_set(kpair->sk->p, p);
    mpz_set(kpair->sk->q, q);
    mpz_set(kpair->sk->n, n);


    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(temp);
    mpz_clear(n);

    return kpair;
}

void encryption::printKeyPair(RabinKeyPair kpair)
{
    cout << "------------- Rabin Keypair -------------" << endl;
    cout << "Rabin Public Key (n): " ;
    printMPZnumber(kpair.pk->n);
    cout << endl << "\t\t-----------------------" << endl;
    cout << "Rabin Private Key (p,q,n): " ;
    printMPZnumber(kpair.sk->p);
    printMPZnumber(kpair.sk->q);
    printMPZnumber(kpair.sk->n);
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

string encryption::encrypt(string plaintext, RabinPublicKey *key)
{
    cout << "\t 1. Integer Representation of Message "<<endl<<endl;
    cout << "Plain Text: " << plaintext << endl;

    string encoded = encode(plaintext);
    cout << "Encoded Plain Text: " << encoded << endl<<endl;

    mpz_t et, ct;
    mpz_init(et);
    mpz_init(ct);

    mpz_set_str(et,encoded.c_str(),10);

    cout << "\t 2. Computation of c = m^e mod n"<<endl<<endl;

    mpz_powm_ui(ct,et,2,key->n);


    char* ciphertext = mpz_get_str(NULL,10,ct);

    cout << "Cipher Text: " << ciphertext << endl<< endl;

    mpz_clear(et);
    mpz_clear(ct);

    return string(ciphertext);
}

void encryption::findSqrtsModPrime(mpz_t sqrt, mpz_t p, mpz_t a)
{

    mpz_t p_plus_1, ex;
    mpz_init(p_plus_1);
    mpz_init(ex);

    //Calculation of ex =(p+1)/4
    mpz_add_ui(p_plus_1,p,1);
    mpz_cdiv_q_ui(ex,p_plus_1,4);

    //Calculation of a^ex (mod p)
    mpz_powm_sec(sqrt, a, ex, p);

    mpz_clear(p_plus_1);
    mpz_clear(ex);
}

string encryption::decrypt(string ciphertext, RabinPrivateKey *key)
{
    cout << "Cipher Text: " <<ciphertext << endl<< endl;

    mpz_t ct;
    mpz_init(ct);
    mpz_set_str(ct,ciphertext.c_str(),10);

    cout << "\t 1. Computation of the two square roots r and -r of modulo p. "<<endl<<endl;

    mpz_t r;
    mpz_init(r);

    findSqrtsModPrime(r,ct,key->p);

    cout << "'r' = ";
    printMPZnumber(r);
    cout << endl<<endl;

    cout << "\t 2. Computation of the two square roots s and -s of modulo q. "<<endl<<endl;

    mpz_t s;
    mpz_init(s);

    findSqrtsModPrime(s,ct,key->q);

    cout << "'s' = ";
    printMPZnumber(s);
    cout << endl<<endl;

    cout << "\t 3. Computation of integers c and d such that cp + dq = 1. "<<endl<<endl;

    mpz_t c,d,gcdext;
    mpz_init(c);
    mpz_init(d);
    mpz_init(gcdext);

    do
    {
        mpz_gcdext(gcdext,c,d,key->p,key->q);
    }
    while(mpz_cmp_ui(gcdext,1)!=0);

    cout << "'c' = ";
    printMPZnumber(c);
    cout << endl << "'d' = ";
    printMPZnumber(d);
    cout << endl<<endl;

     cout << "\t 4. Computation of x = (rdq + scp) (mod n) and y = (rdq - scp) (mod n). "<<endl<<endl;

     mpz_t x, y, tmp1, tmp2;
     mpz_init(x);
     mpz_init(y);
     mpz_init(tmp1);
     mpz_init(tmp2);

     ///tmp1 = rdq
     mpz_mul(tmp1,r,d);
     mpz_mul(tmp1,tmp1,key->q);
     ///tmp2 = scp
     mpz_mul(tmp2,s,c);
     mpz_mul(tmp2,tmp2,key->p);

      cout << "'tmp1' = ";
    printMPZnumber(tmp1);
    cout << endl << "'tmp2' = ";
    printMPZnumber(tmp2);
    cout << endl<<endl;

    ///x = rdq + scp
    mpz_add(x,tmp1,tmp2);

    ///x = (rdq + scp) mod n
    mpz_mod(x,x,key->n);
    mpz_mod(x,x,key->n);

    ///y = rdq - scp
    mpz_sub(y,tmp1,tmp2);

    ///y = (rdq - scp) mod n
    mpz_mod(y,y,key->n);
    mpz_mod(y,y,key->n);

     char* encodedX = mpz_get_str(NULL,10,x);
    cout << "Possible Encoded Plain Text 1: " <<encodedX << endl;

    char* encodedY = mpz_get_str(NULL,10,y);
    cout << "Possible Encoded Plain Text 2: " <<encodedY << endl<< endl;


    string plaintextX = decode(string(encodedX));
    string plaintextY = decode(string(encodedY));

    cout << "\t 5. String Representation of Message "<<endl;
    cout << "Possible Plain Text 1: " << plaintextX << endl << endl;
    cout << "Possible Plain Text 2: " << plaintextY << endl << endl;


    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(c);
    mpz_clear(d);
    mpz_clear(gcdext);
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(tmp1);
    mpz_clear(tmp2);

    return string();
}

