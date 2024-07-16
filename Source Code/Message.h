#ifndef MESSAGE_H
#define MESSAGE_H

#include <iostream>
#include "Bmop.h"
#include "User.h"

enum Raw {CHAR,INT,HEX};

class Message {
    public:
        virtual ~Message();
        
        Message(User* s, User* r, uint32_t* c, uint32_t i, uint32_t ssz, uint32_t asz);
        
        User* getSender     () const { return sender;    } //getters
        User* getReceiver   () const { return receiver;  }
        uint32_t* getContent() const { return content;   }
        uint32_t getStrSize () const { return str_len;   }
        uint32_t getArrSize () const { return arr_len;   }
        uint32_t getIV      () const { return iv;        }
        uint32_t* getSign   () const { return signature; }
        
        std::string makeHeader() const;
        std::string rawContent(Raw setting) const;
        
        bool fromTo(User* s, User* r) const { return sender==s && receiver==r; } //returns true iff it has the specified sender & receiver
        
        static Message* encrypt(Encrypter e, BlockMOP b, User* s, User* r, uint32_t* pub, const string& m); //generates encrypted message
        string decrypt(Encrypter e, BlockMOP b, uint32_t* pub, uint32_t* priv); //decrypts the message
        
        void sign(Encrypter e, uint32_t* pub, uint32_t* priv, const string& m); //adds a signature
        bool verify_sign(Encrypter e, uint32_t* pub, const string& m); //verifies signature
        
        uint32_t* extra; //any extra data needed for decryption
        
        bool read; //whether or not the message was read
        
    protected:
        
    private:
        
        User* sender;    //person its sent from
        User* receiver;  //person its sent to
        uint32_t* content; //text (encrypted)
        uint32_t iv;       //initial value (for block cipher mode of operation)
        
        uint32_t* signature; //signature of the message
        
        int str_len; //size of the text once it's unencrypted
        int arr_len; //size of the encrypted array
        int sig_len; //size of the signature
        int extra_len; //size of the extra
};

#endif // MESSAGE_H
