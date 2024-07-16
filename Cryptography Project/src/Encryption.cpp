#include "Encryption.h"

Encryption::Encryption() {
    //ctor
}

Encryption::~Encryption() {
    //dtor
}

uint32_t Encryption::rsa(uint32_t* param, uint32_t inp) {
    return Discrete::modPow(inp,param[1],param[0]);
}

uint32_t Encryption::elgamal_encrypt(uint32_t* param, uint32_t inp) {
    uint32_t q = param[0], g = param[1], h = param[2], y = param[3]; //assign variable names
    uint32_t s = Discrete::modPow(h,y,q); //compute shared secret, h^y mod q
    uint32_t c2 = (uint32_t)(((uint64_t)inp)*s % q); //multiply message by shared secret
    
    return c2;
}

uint32_t Encryption::elgamal_decrypt(uint32_t* param, uint32_t inp) {
    uint32_t q = param[0], g = param[1], x = param[2], c1 = param[3], c2 = inp;
    uint32_t s = Discrete::modPow(c1,x,q);
    uint32_t sInv = Discrete::modInv(s,q);
    uint32_t m = (uint32_t)(((uint64_t)c2)*sInv % q);
    return m;
}

uint32_t Encryption::caesar(uint32_t* param, uint32_t inp) {
    char* chars = new char[param[1]];
    for(int n=0;n<param[1];n++) {
        char letter = (char)(inp>>((param[1]-1-n)<<3));
        if(letter>='A' && letter<='Z') { letter = (letter+param[0]-'A')%26+'A'; }
        else if(letter>='a' && letter<='z') { letter = (letter+param[0]-'a')%26+'a'; }
        chars[n] = letter;
    }
    uint32_t result = 0;
    for(int n=0;n<param[1];n++) {
        result |= chars[n]<<((param[1]-1-n)<<3);
    }
    return result;
}

uint32_t Encryption::atbash(uint32_t* param, uint32_t inp) {
    char* chars = new char[param[0]];
    for(int n=0;n<param[0];n++) {
        char letter = (char)(inp>>((param[0]-1-n)<<3));
        chars[n] = atbash2(letter);
    }
    uint32_t result = 0;
    for(int n=0;n<param[0];n++) {
        result |= chars[n]<<((param[0]-1-n)<<3);
    }
    return result;
}



char Encryption::atbash2(const char& in) {
    if(in>='a'&&in<='z') { return 'a'+'z'-in; }
    if(in>='A'&&in<='Z') { return 'A'+'Z'-in; }
    return in;
}

std::string Encryption::atbash2(const std::string& in) {
    std::string result = in;
    for(int n=0;result[n]!='\0';n++) {
        result[n] = atbash2(result[n]);
    }
    return result;
}



uint32_t* Encryption::rsaSign(uint32_t* param, const std::string& m) {
    uint32_t hash = Discrete::stringHash(m);
    return new uint32_t[1] {rsa(param,hash)};
}

uint32_t* Encryption::elgamalSign(uint32_t* param, const std::string& m) {
    uint32_t q = param[0], g = param[1], h = param[2], x = param[3]; //assign variables
    uint32_t hash = Discrete::stringHash(m); //load string hash
    uint32_t r, s = 0;
    while(s==0) { //loop as long as s is 0 (since s isn't allowed to be 0)
        
        uint32_t k = rand()%(q-3)+2; //TODO improve so this is only ever odd
        
        uint32_t numer, denom;
        try { denom = Discrete::modInv(k,q-1); } //compute the inverse of k (if failed, regenerate k)
        catch(std::invalid_argument) { continue; }
        
        r = Discrete::modPow(g,k,q); //generate r
        numer = (uint32_t)(((uint64_t)hash+q-1-Discrete::modProd(x,r,q-1))%(q-1)); //generate numerator
        
        s = Discrete::modProd(numer,denom,q-1); //compute s = numer/denom mod q-1
    }
    
    return new uint32_t[2] {r,s};
}

uint32_t* Encryption::plaintextSign(uint32_t* param, const std::string& m) {
    return new uint32_t[1] {Discrete::stringHash(m)}; //just return the message's hash
}


bool Encryption::verify_rsaSign(uint32_t* param, uint32_t* signature, const std::string& m) {
    uint32_t hash = Discrete::stringHash(m) % param[0];
    return hash == rsa(param,signature[0]); //decrypt & compare w/ actual hash
}

bool Encryption::verify_elgamalSign(uint32_t* param, uint32_t* signature, const std::string& m) {
    uint32_t q = param[0], g = param[1], h = param[2], r = signature[0], s = signature[1]; //assign variable names
    uint32_t hash = Discrete::stringHash(m);             //grab the hash
    if(r>=q || s>=q-1) { return false; }                 //verify both signature elements are in the correct modular range
    return Discrete::modPow(g,hash,q) == Discrete::modProd( Discrete::modPow(h,r,q), Discrete::modPow(r,s,q), q); //this is how it is verified that the signature is correct
}

bool Encryption::verify_plaintextSign(uint32_t* param, uint32_t* signature, const std::string& m) {
    return Discrete::stringHash(m) == signature[0];
}


std::function<uint32_t(uint32_t*,uint32_t)> Encryption::encrypt(Encrypter e) { switch(e) {
    case RSA: return Encryption::rsa;
    case ELGAMAL: return Encryption::elgamal_encrypt;
    case CAESAR: return Encryption::caesar;
    case ATBASH: return Encryption::atbash;
    case NONE: return Encryption::nothing;
} }

std::function<uint32_t(uint32_t*,uint32_t)> Encryption::decrypt(Encrypter e) { switch(e) {
    case RSA: return Encryption::rsa;
    case ELGAMAL: return Encryption::elgamal_decrypt;
    case CAESAR: return Encryption::caesar;
    case ATBASH: return Encryption::atbash;
    case NONE: return Encryption::nothing;
} }

std::function<uint32_t*(uint32_t*,const std::string&)> Encryption::sign(Encrypter e) { switch(e) {
    case RSA: return Encryption::rsaSign;
    case ELGAMAL: return Encryption::elgamalSign;
    case CAESAR: case ATBASH: case NONE: return Encryption::plaintextSign;
} }

std::function<bool(uint32_t*,uint32_t*,const std::string&)> Encryption::verify_sign(Encrypter e) { switch(e) {
    case RSA: return Encryption::verify_rsaSign;
    case ELGAMAL: return Encryption::verify_elgamalSign;
    case CAESAR: case ATBASH: case NONE: return Encryption::verify_plaintextSign;
} }






///////////////////////////// THE STUFF BELOW WAS SUPPOSED TO BE USED FOR DES, BUT I RAN OUT OF TIME //////////////////////////////////////////

char Encryption::pc1TableDES[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};

char Encryption::pc2TableDES[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};

char Encryption::ipTableDES[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};

char Encryption::eTableDES[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};

char Encryption::sTablesDES[8][4][16] = {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
                                         {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
                                         {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
                                         {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
                                         {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
                                         {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
                                         {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,13}},
                                         {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};

char Encryption::pTableDES[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};

uint64_t Encryption::mapFromTable(const char* table, uint64_t inp, const uint32_t& length) {
    uint64_t result = 0;
    for(int n=0;n<length;n++) {
        result |= ((inp>>(64-table[n]))&1)<<(63-n);
    }
    return result;
}

uint32_t Encryption::cyclicShift(const uint32_t& inp, const char& shift) {
    if(shift>=0) { return inp<< shift | inp>>(32-shift); }
    else         { return inp>>-shift | inp<<(shift-32); }
}
