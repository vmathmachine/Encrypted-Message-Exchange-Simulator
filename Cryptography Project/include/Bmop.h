#ifndef BMOP_H
#define BMOP_H

#include <string>
#include <functional>
#include "Discrete.h"
#include "Encryption.h"

enum BlockMOP  {ECB,CBC,OFB,CFB};

class Bmop { //Block cipher Mode of OPeration
    public:
        Bmop();
        virtual ~Bmop();
        
        static uint32_t* str_to_arr(std::string inp, uint32_t group);
        static std::string arr_to_str(uint32_t* inp, uint32_t length, uint32_t group);
        
        //electronic code book
        static uint32_t* ecb(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length);
        
        //cipher block chaining mode
        static uint32_t* cbc_encrypt(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length);
        static uint32_t* cbc_decrypt(std::function<uint32_t(uint32_t*,uint32_t)> d, uint32_t* param, const uint32_t* y, uint32_t iv, const uint32_t& length);
        
        //output feedback mode
        static uint32_t* ofb(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length);
        
        //cipher feedback mode
        static uint32_t* cfb_encrypt(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* x, uint32_t iv, const uint32_t& length);
        static uint32_t* cfb_decrypt(std::function<uint32_t(uint32_t*,uint32_t)> e, uint32_t* param, const uint32_t* y, uint32_t iv, const uint32_t& length);
        
        //
        
        static std::function<uint32_t*(std::function<uint32_t(uint32_t*,uint32_t)>,uint32_t*,const uint32_t*,uint32_t,const uint32_t&)> encrypt(BlockMOP b);
        static std::function<uint32_t*(std::function<uint32_t(uint32_t*,uint32_t)>,uint32_t*,const uint32_t*,uint32_t,const uint32_t&)> decrypt(BlockMOP b);
        static bool usesDecryptKey(BlockMOP b);
    protected:
        
    private:
};

#endif // BMOP_H
