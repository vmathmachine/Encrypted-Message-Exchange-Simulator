#include "Message.h"
#include <sstream>

Message::Message(User* s = nullptr, User* r = nullptr, uint32_t* c=nullptr, uint32_t i=0, uint32_t ssz=0, uint32_t asz=0): sender(s), receiver(r), content(c), iv(i), str_len(ssz), arr_len(asz), read(false) {
    
}

Message::~Message() {
    
}

std::string Message::makeHeader() const {
    return "To: "+receiver->getName()+"\nFrom: "+sender->getName();
}

std::string Message::rawContent(Raw setting) const { //prints out raw, un-decrypted content as a hex dump
    std::stringstream s; s<<"Content: ";
    switch(setting) {
        case CHAR: { //char:
            s << Bmop::arr_to_str(content,getStrSize(),2); //convert to a string
        } break;
        case INT: { //int:
            for(int n=0;n<getArrSize();n++) {
                s << content[n] << " "; //print out each individual 32-bit piece
            }
        } break;
        case HEX: { //hex:
            s << "0x";
            char hexigits[16] {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
            for(int n=0;n<getArrSize();n++) { //print out each 32 bit piece, but in hexadecimal
                for(int k=0;k<4;k++) {
                    s << hexigits[(content[n]>>((3-k)<<2))&15];
                }
            }
        } break;
    }
    s << "\nIV: " << iv; //print initial value
    if(sig_len!=0) {
        s << "\nSignature: ";
        for(int n=0;n<sig_len;n++) { s << signature[n] << " "; } //if it exists, print the signature
    }
    return s.str(); //cast to string and return result
}

Message* Message::encrypt(Encrypter e, BlockMOP b, User* s, User* r, uint32_t* pub, const string& m) {
    uint32_t charsPerInt = 2;
    
    uint32_t* param;
    switch(e) {
        case RSA: { param = pub; } break;
        case ELGAMAL: { param = new uint32_t[4] {pub[0],pub[1],pub[2],rand()%(pub[0]-1)+1}; } break;
        case CAESAR: { param = new uint32_t[2] {pub[0],charsPerInt}; } break;
        case ATBASH: { param = new uint32_t[1] {charsPerInt}; } break;
        case NONE: { param = nullptr; } break;
    }
    
    uint32_t iv = rand() & (1<<28)-1; //randomize IV (make sure that it's less than the modulo, otherwise the decryption isn't necessarily unique)
    //the smallest the modulo could be is 2^28, and the largest the message could be is 2^24, so as long as the iv is smaller than 2^28, the largest m XOR iv could be is 2^28-1
    ///NOTE the above change was made after the project was already turned in
    
    uint32_t* arr = Bmop::str_to_arr(m,charsPerInt);
    
    uint32_t* encrypted = (Bmop::encrypt(b))(Encryption::encrypt(e), param, arr, iv, m.size());
    
    
    Message* msg = new Message(s,r,encrypted,iv,m.size(),(m.size()+charsPerInt-1)/charsPerInt);
    
    if(e==ELGAMAL) {
        msg->extra = new uint32_t[1] {Discrete::modPow(pub[1],param[3],pub[0])};
    }
    
    return msg;
}

string Message::decrypt(Encrypter d, BlockMOP b, uint32_t* pub, uint32_t* priv) {
    uint32_t charsPerInt = 2;
    
    bool decrypts = Bmop::usesDecryptKey(b);
    
    auto func = decrypts ? Encryption::decrypt(d) : Encryption::encrypt(d);
    auto mop = decrypts ? Bmop::decrypt(b) : Bmop::encrypt(b);
    
    uint32_t* param;
    if(decrypts) {
        switch(d) {
            case     RSA: { param = new uint32_t[2] {pub[0],priv[0]};                 } break;
            case ELGAMAL: { param = new uint32_t[4] {pub[0],pub[1],priv[0],extra[0]}; } break;
            case CAESAR: { param = new uint32_t[2] {pub[0]==0?pub[0]:26-pub[0],charsPerInt}; } break;
            case ATBASH: { param = new uint32_t[1] {charsPerInt}; } break;
            case NONE: { param = nullptr; } break;
        }
    }
    else {
        switch(d) {
            case RSA: { param = pub; } break;
            case ELGAMAL: { param = new uint32_t[4] {pub[0],pub[1],pub[2],extra[0]}; } break; //OH NO
            case CAESAR: { param = pub; } break;
            case ATBASH: case NONE: { param = nullptr; } break;
        }
    }
    
    uint32_t* arr = mop(func, param, getContent(), iv, getArrSize());
    
    return Bmop::arr_to_str(arr,getStrSize(),charsPerInt);
}

void Message::sign(Encrypter e, uint32_t* pub, uint32_t* priv, const string& m) { //adds a signature
    uint32_t* param;
    switch(e) {
        case RSA: { param = new uint32_t[2] {pub[0],priv[0]}; sig_len = 1; } break;
        case ELGAMAL: { param = new uint32_t[4] {pub[0],pub[1],pub[2],priv[0]}; sig_len = 2; } break;
        case CAESAR: case ATBASH: case NONE: { param = new uint32_t[0]; sig_len = 1; } break;
    }
    signature = Encryption::sign(e)(param, m);
}

bool Message::verify_sign(Encrypter e, uint32_t* pub, const string& m) {
    uint32_t* param;
    switch(e) {
        case RSA: { param = pub; } break;
        case ELGAMAL: { param = pub; } break;
        case CAESAR: case ATBASH: case NONE: { param = pub; } break;
    }
    return Encryption::verify_sign(e)(param,signature,m);
}
