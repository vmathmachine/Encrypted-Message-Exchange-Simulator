#include "User.h"
#include "Message.h"

User* User::curr = nullptr;

User::User() {
    
}

User::~User() {
    
}

User::User(const string& n): name(n) {
    
}

void User::greet() { std::cout << "Welcome, " << name << endl; }

void User::pushMessage(Message* msg, const std::string& content) {
    saved[msg] = content;
}

std::string User::loadMessage(Message* msg) {
    return saved[msg];
}

void User::genKey_RSA(const uint16_t& p, const uint16_t& q) { //REQUISITE: p and q must be prime
    
    uint32_t n = ((uint32_t)p)*((uint32_t)q); //find their product
    uint32_t tot = (uint32_t)Discrete::lcm(p-1,q-1); //find the carmichael totient (the smallest # primitive roots must be raised to to become 1)
    
    uint32_t e = 65537; //choose the encryption key
    while(Discrete::gcd(e,tot)!=1) { ++e; } //if the encryption key isn't coprime to the totient, choose another encryption key
    
    uint32_t d = Discrete::modInv(e,tot); //find the decryption key, e^-1 mod totient
    
    publicKey  = new uint32_t[2] {n,e}; //the modulo and encryption key are public
    privateKey = new uint32_t[1] {d};   //the decryption key is private
    
    publicSize = 2;
    privateSize = 1;
    
    saveSecret(this, privateKey); //save your own private key (because of course you know your private key)
}

void User::genKey_RSA() {
    genKey_RSA(Discrete::randomPrime(16384,65535), Discrete::randomPrime(16384,65535)); //generate random 16-bit primes (but don't make them too small)
}

void User::genKey_Elgamal(const uint32_t& q) { //REQUISITE: q must be prime
    
    uint32_t g = Discrete::makeGenerator(q); //load a generator for this cyclic group
    
    uint32_t x = rand()%(q-2) + 1; //load private key
    uint32_t h = Discrete::modPow(g,x,q);
    
    publicKey = new uint32_t[3] {q,g,h};
    privateKey = new uint32_t[1] {x};
    
    publicSize = 3;
    privateSize = 1;
    
    saveSecret(this, privateKey); //save your own private key (because of course you know your private key)
}

void User::genKey_Elgamal() {
    genKey_Elgamal(Discrete::randomPrime(1073741824,4294967295));
}

void User::genKey_Caesar(int s) {
    s%=26; if(s<0) { s+=26; }
    publicKey = new uint32_t[1] {s};
    privateKey = new uint32_t[1] {s==0?0:26-s};
    
    publicSize = 1;
    privateSize = 1;
    
    saveSecret(this, privateKey);
}

void User::genKey_Caesar() {
    genKey_Caesar(rand()%26);
}

void User::genKey_None() {
    publicKey = new uint32_t[0];
    privateKey = new uint32_t[0];
    
    publicSize = privateSize = 0;
    saveSecret(this, privateKey);
}

void User::genKey(Encrypter method) {
    switch(method) {
        case RSA: genKey_RSA(); break;
        case ELGAMAL: genKey_Elgamal(); break;
        case CAESAR: genKey_Caesar(); break;
        case ATBASH: case NONE: genKey_None(); break;
        
        default: throw std::invalid_argument("It appears genKey was not initialized for this encryption method");
    }
}


/*uint32_t* User::encrypt(std::function<uint32_t*(uint32_t*,uint32_t)> e,
                      std::function<uint32_t*(std::function<uint32_t*(uint32_t*,uint32_t)>, uint32_t*, const uint32_t*, uint32_t, const uint32_t&)> b,
                      uint32_t* param, const uint32_t* m, uint32_t iv, const uint32_t& length) {
    return b(e, param, m, iv, length);
}*/
