#include "Bmop.h"

Bmop::Bmop() {
    //ctor
}

Bmop::~Bmop() {
    //dtor
}

/*uint32_t* Bmop::str_to_arr(std::string inp) {
    uint32_t* result = new uint32_t[(inp.size()+1)>>1];
    for(int n=0;(n<<1)<inp.size();n++) {
        result[n] = ((uint32_t)inp[n<<1]) | ((uint32_t)inp[n<<1|1])<<8;
    }
    return result;
}*/

uint32_t* Bmop::str_to_arr(std::string inp, uint32_t group) {
    uint32_t* result = new uint32_t[(inp.size()+group-1)/group];
    for(int n=0;n*group<inp.size();n++) {
        result[n] = 0;
        for(int k=0;k<group;k++) { result[n] |= ((uint32_t)inp[group*n+k])<<((group-1-k)<<3); }
    }
    return result;
}

/*std::string Bmop::arr_to_str(uint32_t* inp, uint32_t length) {
    char str[length+1];
    for(int n=0;n<length;n++) {
        str[n] = (char)(inp[n>>1]>>((n&1)<<3));
    }
    str[length] = '\0'; //add terminating character
    return str;
}*/

std::string Bmop::arr_to_str(uint32_t* inp, uint32_t length, uint32_t group) {
    char str[length+1];
    for(int n=0;n<length;n++) {
        str[n] = (char)(inp[n/group]>>((group-1-n%group)<<3));
    }
    str[length] = '\0'; //add terminating character
    return str;
}

uint32_t* Bmop::ecb(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length) {
    uint32_t* y = new uint32_t[length]; //initialize output stream
    
    for(int n=0;n<length;n++) {
        y[n] = e(param, x[n]);
    }
    return y;
}

uint32_t* Bmop::cbc_encrypt(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length) {
    uint32_t* y = new uint32_t[length]; //initialize y
    y[0] = e(param, x[0] ^ iv);
    for(int n=1;n<length;n++) {
        y[n] = e(param, x[n] ^ y[n-1]);
    }
    return y;
}

uint32_t* Bmop::cbc_decrypt(std::function<uint32_t(uint32_t*,uint32_t)> d, uint32_t* param, const uint32_t* y, uint32_t iv, const uint32_t& length) {
    uint32_t* x = new uint32_t[length]; //initialize x
    x[0] = iv ^ d(param, y[0]);
    for(int n=1;n<length;n++) {
        x[n] = y[n-1] ^ d(param, y[n]);
    }
    return x;
}

uint32_t* Bmop::ofb(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length) {
    uint32_t* y = new uint32_t[length]; //initialize y
    uint32_t s = e(param, iv); //init s
    for(int n=0;n<length;n++) {
        y[n] = x[n] ^ s;  //xor x with s
        s = e(param, iv); //update s
    }
    return y;
}

uint32_t* Bmop::cfb_encrypt(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length) {
    uint32_t* y = new uint32_t[length]; //initialize y
    y[0] = x[0] ^ e(param, iv);
    for(int n=1;n<length;n++) {
        y[n] = x[n] ^ e(param, y[n-1]);
    }
    return y;
}

uint32_t* Bmop::cfb_decrypt(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* y, uint32_t iv, const uint32_t& length) {
    uint32_t* x = new uint32_t[length]; //initialize x
    x[0] = y[0] ^ e(param, iv);
    for(int n=1;n<length;n++) {
        x[n] = y[n] ^ e(param, y[n-1]);
    }
    return x;
}



std::function<uint32_t*(std::function<uint32_t(uint32_t*,uint32_t)>,uint32_t*,const uint32_t*,uint32_t,const uint32_t&)> Bmop::encrypt(BlockMOP b) { switch(b) {
    case ECB: return Bmop::ecb;
    case CBC: return Bmop::cbc_encrypt;
    case OFB: return Bmop::ofb;
    case CFB: return Bmop::cfb_encrypt;
} }

std::function<uint32_t*(std::function<uint32_t(uint32_t*,uint32_t)>,uint32_t*,const uint32_t*,uint32_t,const uint32_t&)> Bmop::decrypt(BlockMOP b) { switch(b) {
    case ECB: return Bmop::ecb;
    case CBC: return Bmop::cbc_decrypt;
    case OFB: return Bmop::ofb;
    case CFB: return Bmop::cfb_decrypt;
} }

bool Bmop::usesDecryptKey(BlockMOP b) { switch(b) {
    case ECB: case CBC: return  true; //these modes require decryption key to decrypt
    default:            return false; //these modes can be decrypted with the encryption key
} }
