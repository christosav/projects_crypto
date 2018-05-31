
// constructing vectors
#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>

#include "RSA.cpp"
#include "RSA.h"

using namespace std;

void writeKeys(RSAKeyPair);
RSAPublicKey* readPublicKey();
RSAPrivateKey* readPrivateKey();
void writeFile(string,string );
string readFile(string );
bool fileExists (const string& );

int main(void)
{
    RSAEncryption RSA;
    RSAKeyPair* keypair;
    RSAPublicKey* pk;
    RSAPrivateKey* sk;

    string filename,plain,encrypted,decrypted;
    int option;

    do
    {
        cout << "1. Generate keys." << endl;
        cout << "2. Encrypt file." << endl;
        cout << "3. Decrypt file." << endl;
        cout << "4. Exit." << endl;
        cout << "$ ";
        cin >> option;
        cout << endl;

        switch(option)
        {
        case 1:
            cout << " ** KeyPair Generation **" << endl<< endl;
            keypair = RSA.generateKeyPair(512); //generation
            RSA.printKeyPair(*keypair);  //show
            writeKeys(*keypair); //write to file
            break;
        case 2:
            cout << " ** File Encryption **" << endl<< endl;
            if(fileExists("public.key")!=1) //check if public key file exists
            {
                cerr << "Public Key file 'public.key' not exists!" << endl << endl;
                break;
            }
            cout << "Filename: ";
            cin >> filename;

            plain = readFile(filename); //read contents
            pk = readPublicKey(); //read public key

            encrypted = RSA.encrypt(plain,*pk); //encrypt contents with public key

            writeFile(filename,encrypted); //write encrypted contents

            cout << endl << "File '" << filename << "' encrypted." << endl << endl;
            break;
        case 3:
            cout << " ** File Encryption **" << endl<< endl;
            if(fileExists("private.key")!=1) //check if private key file exists
            {
                cerr << "Private Key file 'private.key' not exists!" << endl << endl;
                break;
            }
            cout << "Filename: ";
            cin >> filename;

            encrypted = readFile(filename); //read contents
            sk = readPrivateKey(); //read private key

            decrypted = RSA.decrypt(encrypted,*sk); //decrypt contents with private key

            writeFile(filename,decrypted); //write decrypted contents

            cout << endl << "File '" << filename << "' decrypted." << endl << endl;
            break;
        }

        cout << endl;
    }
    while(option!=0);

    return EXIT_SUCCESS;
}

///Extract keys to file
void writeKeys(RSAKeyPair keys)
{
    char* N_str = mpz_get_str(NULL,10,keys.pk->N);
    char* e_str = mpz_get_str(NULL,10,keys.pk->e);
    char* d_str = mpz_get_str(NULL,10,keys.sk->d);

    ofstream out("public.key");
    out << e_str << endl;
    out << N_str << endl;
    out.close();

    N_str = mpz_get_str(NULL,10,keys.sk->N);

    out.open("private.key");
    out << d_str << endl;
    out << N_str << endl;
    out.close();

    cout << "Files public.key and private.key saved." <<endl;
}

///Read Public Key from file
RSAPublicKey* readPublicKey()
{
    RSAPublicKey* pk = new RSAPublicKey();

    string line;

    ifstream in("public.key");

    getline(in, line);
    mpz_set_str(pk->e, line.c_str(),10);

    getline(in, line);
    mpz_set_str(pk->N, line.c_str(),10);

    in.close();

    return pk;
}

///Read Private Key from file
RSAPrivateKey* readPrivateKey()
{
    RSAPrivateKey* sk = new RSAPrivateKey();

    string line;

    ifstream in("private.key");

    getline(in, line);
    mpz_set_str(sk->d, line.c_str(),10);

    getline(in, line);
    mpz_set_str(sk->N, line.c_str(),10);

    in.close();

    return sk;
}

///Write contents to a file
void writeFile(string filename,string content)
{
    ofstream out(filename.c_str());
    out << content;
    out.close();
}

///Read contents of a file
string readFile(string filename)
{
    ifstream ifs(filename.c_str());
    string content((istreambuf_iterator<char>(ifs)),
                   (istreambuf_iterator<char>()));
    return content;
}
///Check if file exists
bool fileExists (const std::string& filename)
{
    return (access(filename.c_str(), F_OK) != -1);
}
