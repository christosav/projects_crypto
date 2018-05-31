#ifndef RSA_H
#define RSA_H

#include <gmpxx.h>

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
    std::string encode(const std::string &);
    std::string decode(const std::string &);
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
    std::string encrypt(std::string,const RSAPublicKey);
    std::string decrypt(std::string,const RSAPrivateKey);
};

#endif
