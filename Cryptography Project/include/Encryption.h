#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <iostream>
#include <functional>
#include "Discrete.h"

enum Encrypter {RSA,ELGAMAL,CAESAR,ATBASH,NONE};

class Encryption {
    public:
        Encryption();
        virtual ~Encryption();
        
        static uint32_t rsa(uint32_t* key, uint32_t inp); //{mod,power} input
        
        static uint32_t elgamal_encrypt(uint32_t* key, uint32_t inp); //{mod,gen,h,y} input
        static uint32_t elgamal_decrypt(uint32_t* key, uint32_t inp); //{mod,gen,x,c1} c2
        
        static uint32_t caesar(uint32_t* key, uint32_t inp); //{shift,chars per int} input
        
        static uint32_t atbash(uint32_t* key, uint32_t inp); //{chars per int} input
        
        static uint32_t nothing(uint32_t* key, uint32_t inp) { return inp; } //{} input
        
        static char atbash2(const char& in);
        static std::string atbash2(const std::string& in);
        
        
        
        static uint32_t* rsaSign(uint32_t* key, const std::string& m); //{mod,power} message
        static uint32_t* elgamalSign(uint32_t* key, const std::string& m); //{mod,gen,h,x} message
        static uint32_t* plaintextSign(uint32_t* key, const std::string& m); //{} message
        
        
        static bool verify_rsaSign(uint32_t* param, uint32_t* signature, const std::string& m); //{mod,power^-1} {signature} message
        static bool verify_elgamalSign(uint32_t* param, uint32_t* signature, const std::string& m); //{mod,gen,h} {r,s} message
        static bool verify_plaintextSign(uint32_t* param, uint32_t* signature, const std::string& m); //{} {} message
        
        
        static std::function<uint32_t(uint32_t*,uint32_t)> encrypt(Encrypter e); //grabs encrypt function
        static std::function<uint32_t(uint32_t*,uint32_t)> decrypt(Encrypter e); //grabs decrypt function
        static std::function<uint32_t*(uint32_t*,const std::string&)> sign(Encrypter e); //grabs signature function
        static std::function<bool(uint32_t*,uint32_t*,const std::string&)> verify_sign(Encrypter e); //grabs function to verify signature
        
        
        
        
        /////////////////////// The below stuff was meant to be used for DES, but I had too much trouble implementing DES ////////////////////////
        
        static uint64_t mapFromTable(const char* table, uint64_t inp, const uint32_t& length);
        static uint32_t cyclicShift(const uint32_t& inp, const char& shift);
        
        static char pc1TableDES[56];
        static char pc2TableDES[48];
        static char ipTableDES[64];
        static char eTableDES[48];
        static char sTablesDES[8][4][16];
        static char pTableDES[32];
        
    protected:
        
    private:
};

#endif // ENCRYPTION_H
