#ifndef USER_H
#define USER_H

#include <iostream>
#include <string>

#include "Bmop.h"
#include "Discrete.h"
#include "Encryption.h"

using namespace std;

/*struct Key { //stores encryption/decryption keys
    char* bytes;
    Key(
};*/

class Message;

class User {
    public:
        User();
        virtual ~User();
        
        User(const std::string& n);
        
        void greet();
        
        string getName() const { return name; }
        void setName(const string& n2) { name = n2; }
        
        uint32_t* getPublic() const { return publicKey; } //returns the public key
        uint32_t* getPrivate() const {
            if(this!=curr) { throw new std::invalid_argument("You cannot see this person's private key!"); }
            ///The above /|\ check is put here to make sure we can never cheat. You can only view your own private keys
            return privateKey;
        }
        uint32_t getPublicSize() const { return publicSize; }
        uint32_t getPrivateSize() const { return privateSize; }
        
        void pushMessage(Message* msg, const std::string& content);
        std::string loadMessage(Message* msg);
        
        void genKey_RSA(const uint16_t& p, const uint16_t& q); //generates public & private key using RSA algorithm
        void genKey_Elgamal(const uint32_t& q); //generates public & private key using Elgamal algorithm
        void genKey_Caesar(int s); //assigns Caesar encryption key
        
        void genKey_RSA(); //generates RSA key with randomized primes
        void genKey_Elgamal(); //generates Elgamal key with randomized prime
        void genKey_Caesar(); //generates Caesar encryption key
        void genKey_None(); //generates key for no encryption
        
        void genKey(Encrypter method); //generates key given the encryption method
        
        
        void saveSecret(User* sucker, uint32_t* keys) { secrets[sucker] = keys; }
        bool hasSecret(User* sucker) { return secrets.contains(sucker); }
        uint32_t* getSecret(User* sucker) { return secrets[sucker]; }
        void removeSecret(User* rem) { secrets.erase(rem); }
        
        bool hasSaved(Message* mess) { return saved.contains(mess); }
        
        static User* curr; //the current user
        
    protected:
        
    private:
        string name;
        
        uint32_t* privateKey; //private key
        uint32_t* publicKey;  //public key
        
        uint32_t privateSize; //size of private key
        uint32_t publicSize;  //size of public key
        
        std::map<Message*, std::string> saved; //saved messages that have been sent by this user
        /** Many systems have different ways of letting users see messages they already sent. Some systems will store a copy of the unencrypted message on their own device (like text messages),
        some store them on a third party server and forbid access to anybody but the sender or receiver, and some don't even have to worry about this issue because the encryption is symmetric.
        To keep this simulation agnostic towards all scenarios, we're storing an unencrypted copy on the sender's device. For the sake of argument, let's assume this unencrypted copy is
        forbidden from bypassing the user's firewall.
        **/
        
        std::map<User*, uint32_t*> secrets; //private keys that this hacker has discovered
};

#endif // USER_H
