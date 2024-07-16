#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "User.h"
#include "Message.h"
#include "Discrete.h"
#include "Bmop.h"
#include "Encryption.h"

using namespace std;

string requestUser(map<string,User*>& users, bool canExist, bool shouldExist, bool canCancel); //requests the user from the cin buffer

void allowSpaces(const bool& allow); //changes whether space is interpreted as normal character or a delimiter for cin

//all the menu options
enum Menu {HOME,SEND,READ,READ_RAW,SU,KEYS,HACK,ADMIN,SETTINGS,USERADD,USERDEL,USERMOD,SNOOP,SPOOF,SAVE_KEYS,VIEW_KEYS,REMOVE_KEYS,MATH,FACTOR,TOTIENT,LOG,POW,INV,MUL,GCD,LCM,RAW_MODE,PRIV_MODE};


///CREDIT FOR THE BELOW CODE SNIPPET GOES TO https://www.geeksforgeeks.org/how-to-take-std-cin-input-with-spaces-in-cpp/
///Without this code, I would not be able to write messages that include whitespace characters

struct changeDelimiter : ctype<char> {
    changeDelimiter() : ctype<char>( createTable()) { } //constructor for changeDelimiter, initializing the base class with a table
    static mask const* createTable() { //static function to create a table with custom settings
        static mask rc[table_size];    //creating a table with the size of the character set
        rc['\n'] = ctype_base::space;  //set the newline character to be treated as whitespace
        return rc;                     //return the modified table
    }
};

///END CODE SNIPPET

struct resetDelimiter : ctype<char> {
    resetDelimiter() : ctype<char>( createTable()) { } //constructor for resetDelimiter, initializing the base class with a table
    static mask const* createTable() { //static function to create a table with custom settings
        static mask rc[table_size];    //creating a table with the size of the character set
        rc['\n'] = ctype_base::space;  //set the newline character to be treated as whitespace
        rc[' ']  = ctype_base::space;  //set the space character to be treated as whitespace
        return rc;                     //return the modified table
    }
};

int main() {
    
    srand(time(NULL)); //initialize random number generator
    
    
    /////////////////////// DECLARE IMPORTANT VARIABLES /////////////////////////
    
    map<string, User*> users; //list of users by username
    
    Menu menu = HOME; //current mode in the menu
    
    vector<Message*>* msgList = new vector<Message*>(); //list of all messages that have been sent
    
    User* user; //the current user
    
    Raw rawSetting = CHAR; //how raw text is displayed
    bool privSetting = true; //whether or not the user's PERSONAL private key is displayed in the key display menu
    
    /////////////////////// CHOOSE INITIAL SETTINGS /////////////////////////////
    
    cout << "Encrypted message exchange simulator (by Chris Maguschak)\n\nMost operations can be canceled via the word CANCEL\n\n\n\n";
    
    
    cout << "Which encryption method would you like to use for further messages?\n" <<
            "1. RSA Encryption\n2. ElGamal Encryption\n3. Caesar cipher\n4. Atbash cipher\n5. No encryption\n\n"; //choose the encryption method
    int option; cin >> option;
    Encrypter encryptMethod;
    switch(option) {
        case 1: encryptMethod = RSA; break;
        case 2: encryptMethod = ELGAMAL; break;
        case 3: encryptMethod = CAESAR; break;
        case 4: encryptMethod = ATBASH; break;
        case 5: encryptMethod = NONE; break;
    }
    
    cout << "\nWhich block cipher mode of operation would you like to use?\n" << //choose the block cipher mode of operation
            "1. Electronic Code Book (ECB)\n2. Cipher Block Chaining mode (CBC)\n3. Output FeedBack mode (OFB)\n4. Cipher FeedBack mode (CFB)\n\n";
    cin >> option;
    BlockMOP bmop;
    switch(option) {
        case 1: bmop = ECB; break;
        case 2: bmop = CBC; break;
        case 3: bmop = OFB; break;
        case 4: bmop = CFB; break;
    }
    
    cout << "\nAnd lastly, would you like to use signatures?\n1. Yes\n2. No\n\n"; //choose whether to have signatures
    cin >> option;
    
    bool signatures = option==1;
    
    
    /////////////////////////// INITIALIZE VARIABLES ////////////////////////////////////////////
    
    users[  "Alice"] = new User(  "Alice"); //user 1
    users[    "Bob"] = new User(    "Bob"); //user 2
    users["Charlie"] = new User("Charlie"); //man in the middle (hacker)
    
    for(auto it : users) { it.second->genKey(encryptMethod); } //generate a key for each user
    
    user = users["Alice"]; //initialize current user to Alice
    User::curr = user;     //this is the only person whose private keys we can see (at least until we switch users)
    
    
    ///////////////////////////// MODE OF OPERATION /////////////////////////////////////////////
    
    user->greet(); //greet the current user
    cout << endl;
    
    //NOTE: I know the below structure is kind of spaghetti code, but I couldn't think of any better ways to write this that wouldn't be a pain in the butt, so I just went with this
    bool running = true; //when false, the program ends
    while(running) {     //run a continuous loop
        switch(menu) {   //what we do each iteraation depends on what mode we're in
            case HOME: { ///HOME MENU
                
                int numUnread = 0; //first, determine how many unread messages there are
                for(Message* m : *msgList) {
                    if(m->getReceiver()==user && !m->read) { ++numUnread; } //count the number of messages addressed to the user but not yet read
                }
                
                cout << "\nOptions: (you are " << user->getName() << ")\n1. Send message\n2. Read your conversations"; //display options
                if(numUnread!=0) { cout << " (" << numUnread << ")"; }            //(show how many unread messages)
                cout << "\n3. Change role\n4. View all messages (encrypted)\n5. View public keys\n6. Hacking tools\n7. Admin\n8. Settings\n9. Exit\n\n"; //display the rest of the options
                int option; cin >> option; //request the option
                switch(option) {
                    case 1: menu=SEND;     break;
                    case 2: menu=READ;     break;
                    case 3: menu=SU;       break;
                    case 4: menu=READ_RAW; break;
                    case 5: menu=KEYS;     break;
                    case 6: menu=HACK;     break;
                    case 7: menu=ADMIN;    break;
                    case 8: menu=SETTINGS; break;
                    case 9: running=false; break;
                }
                cout << endl;
            } break;
            case SEND: { ///SENDING A MESSAGE
                allowSpaces(true); //allow spaces to be interpreted as regular text
                
                cout << "To: "; //ask who the message is for
                string name = requestUser(users, true, true, true); //request the user's name (must exist)
                if(name!="CANCEL") {                                //if not canceled:
                    User* receiver = users[name];                   //grab receiver
                    cout << "From: " << user->getName() << endl;    //display sender
                    cout << "Message: ";                            //ask for message
                    string message; cin >> message;                 //get message
                    
                    cout << "\nSending...\n"; //indicate the message is being sent
                    
                    Message* msg = Message::encrypt(encryptMethod, bmop, user, receiver, receiver->getPublic(), message); //generate the encrypted message
                    
                    if(signatures) { msg->sign(encryptMethod,user->getPublic(),user->getPrivate(), message); } //if applicable, sign the message
                    
                    user->pushMessage(msg, message); //save the unencrypted copy to the sender's local device
                    msgList->push_back(msg);         //send the encrypted message to the cloud
                    
                    
                    cout << "Sent\n\n"; //verify the message has been sent
                }
                
                allowSpaces(false); //turn spaces back into delimiters
                
                menu = HOME;        //go back to the home menu
            } break;
            case READ: { ///READ ALL MESSAGES IN A CONVERSATION
                
                //first, show who we have unread messages from
                map<User*,int> unread; //record unread messages person-by-person
                for(Message* msg : *msgList) { if(msg->getReceiver()==user && !msg->read) { //loop through all messages that are addressed to this user and unread
                    if(!unread.contains(msg->getSender())) { unread[msg->getSender()] = 1; } //if not declared for this sender, init to 1
                    else                                   { unread[msg->getSender()]++;   } //otherwise, increment
                } }
                
                for(auto it : unread) { //display number of unread messages person-by-person
                    cout << it.first->getName() << ": " << it.second << " unread\n";
                }
                
                cout << "\nWith whom?\n"; //ask who to read the conversation with
                string name = requestUser(users, true, true, true); //request name of user (user must exist)
                
                if(name!="CANCEL") {            //if we don't cancel
                    cout << "=================================\n"; //divider
                    User* person = users[name]; //grab the person we want to send this message
                    
                    for(Message* msg : *msgList) {     //loop through all messages
                        if(msg->fromTo(person,user)) { //if the message is from this person, to the user:
                            cout << msg->makeHeader() << endl; //display to/from
                            
                            string contents = msg->decrypt(encryptMethod, bmop, user->getPublic(), user->getPrivate()); //decrypt the message
                            
                            if(signatures) {                                                                   //if we're using signatures
                                bool correct = msg->verify_sign(encryptMethod, person->getPublic(), contents); //verify authenticity
                                if(!correct) { cout << "(Spoofed)\n"; }                                        //if not authentic, indicate it's a spoof
                            }
                            
                            cout << contents << "\n=================================\n"; //separate messages
                            
                            msg->read = true; //the message has now been read
                        }
                        else if(user->hasSaved(msg) && msg->getReceiver()==person) { //Otherwise, if this user has a saved copy of this message (and it was sent to the person in question)
                            cout << msg->makeHeader() << endl;                       //display the to/from
                            if(msg->getSender() != user) { cout << "(Spoofed)\n"; }  //if the user isn't listed as the sender, this was very obviously spoofed (by the user)
                            cout << user->loadMessage(msg) << "\n=================================\n"; //grab the message from local storage (and separate messages)
                        }
                    }
                    cout << "\n";
                }
                menu = HOME; //go back to the home menu
            } break;
            case SU: { /// SWITCH USER
                cout << "To?\n"; //ask who you want to switch to
                string name = requestUser(users,true,true,true); //request the user's name (must exist)
                cout << endl;
                if(name!="CANCEL") { //if we don't cancel:
                    user = users[name]; User::curr = user; //change the user (also changing whose private keys we can view)
                    user->greet();   //greet the user
                    cout << endl;    //next line
                }
                menu = HOME; //go back to the home menu
            } break;
            case READ_RAW: { /// READ RAW MESSAGES
                cout << "=================================\n";
                for(Message* msg : *msgList) { //loop through all messages
                    cout << msg->makeHeader() << endl; //show the to/from
                    cout << msg->rawContent(rawSetting) << "\n=================================\n"; //display raw content and separate messages
                }
                cout << "\n"; //next line
                menu =  HOME; //go back to the home menu
            } break;
            case KEYS: { /// DISPLAY THE PUBLIC KEYS
                
                switch(encryptMethod) { //label the keys for clarity as to what each part does
                    case     RSA: cout << "Name: mod, power\n\n"; break;
                    case ELGAMAL: cout << "Name: mod, generator, h\n\n"; break;
                    case  CAESAR: cout << "Name: shift\n\n"; break;
                    case ATBASH: case NONE: cout << "Name: \n\n"; break;
                }
                
                for(auto it : users) {        //loop through all users
                    cout << it.first << ": "; //display their name
                    for(int n=0;n<it.second->getPublicSize();n++) { //and all their public keys
                        if(n!=0) { cout << ", "; }
                        cout << it.second->getPublic()[n];
                    }
                    cout << endl;
                }
                if(privSetting) {
                    cout << "(Your private key: "; //also display the private key
                    for(int n=0;n<user->getPrivateSize();n++) {
                        if(n!=0) { cout << " "; }
                        cout << user->getPrivate()[n];
                    }
                    cout << ")\n";
                }
                cout << endl;
                
                menu = HOME; //go back to home menu
            } break;
            case HACK: { ///HACKING INTERFACE
                
                cout << "\nTools for man in the middle attacks\n\n";
                cout << "1. <- Go Back\n2. Snoop\n3. Spoof\n4. Save/Edit keys\n5. View keys\n6. Remove keys\n7. Math tools\n\n";
                int option; cin >> option;
                switch(option) {
                    case 1: menu=HOME;        break;
                    case 2: menu=SNOOP;       break;
                    case 3: menu=SPOOF;       break;
                    case 4: menu=SAVE_KEYS;   break;
                    case 5: menu=VIEW_KEYS;   break;
                    case 6: menu=REMOVE_KEYS; break;
                    case 7: menu=MATH;        break;
                }
                cout << "\n";
            } break;
            case SNOOP: {
                for(Message* msg : *msgList) {
                    cout << msg->makeHeader() << endl;
                    if(user->hasSaved(msg)) {
                        cout << user->loadMessage(msg) << "\n=================================\n";
                    }
                    else if(user->hasSecret(msg->getReceiver())) {
                        
                        string contents = msg->decrypt(encryptMethod,bmop,msg->getReceiver()->getPublic(),user->getSecret(msg->getReceiver()));
                        
                        if(signatures) {                                                                             //if we're using signatures
                            bool correct = msg->verify_sign(encryptMethod, msg->getSender()->getPublic(), contents); //verify authenticity
                            if(!correct) { cout << "(Spoofed)\n"; }                                                  //if not authentic, indicate it's a spoof
                        }
                        
                        cout << contents << "\n=================================\n";
                    }
                    else {
                        cout << msg->rawContent(rawSetting) << "\n=================================\n";
                    }
                }
                menu = HACK;
            } break;
            case SPOOF: {
                cout << "To: ";
                string to = requestUser(users, true, true, true);
                if(to!="CANCEL") {
                    cout << "From: ";
                    string from = requestUser(users, true, true, true);
                    if(from!="CANCEL") {
                        //From here, add the ability to send messages as a hacker, and the ability to decide if you want to spoof anybody's signature
                        
                        User* receiver = users[to]; User* sender = users[from];
                        
                        allowSpaces(true);
                        
                        cout << "Message: ";
                        string message; cin >> message;
                        
                        cout << "\nSending...\n";
                        
                        Message* msg = Message::encrypt(encryptMethod, bmop, sender, receiver, receiver->getPublic(), message);
                        
                        if(signatures) { //if signatures are enabled:
                            uint32_t* priv; //we need to sign it using a private key
                            if(user->hasSecret(sender)) { priv = user->getSecret(sender); } //if we know the "sender"'s private key, use that
                            else                        { priv = user->getPrivate();      } //otherwise...um...let's just use our own key. Maybe no one will notice?
                            
                            msg->sign(encryptMethod,sender->getPublic(),priv, message);
                        }
                        
                        user->pushMessage(msg, message);
                        msgList->push_back(msg);
                        
                        
                        cout << "Sent\n\n";
                        
                        allowSpaces(false);
                    }
                }
                
                menu = HACK;
            } break;
            case SAVE_KEYS: {
                cout << "If you manage to uncover someone's private key, you can save it here.\n";
                cout << "Whose key? ";
                string name;
                while(true) {
                    name = requestUser(users,true,true,true);
                    if(name==user->getName()) {
                        cout << "Cannot change your own stored private key. Try again\n";
                        continue;
                    }
                    break;
                }
                if(name!="CANCEL") {
                    User* sucker = users[name];
                    cout << "key: ";
                    uint32_t* keys = new uint32_t[sucker->getPrivateSize()];
                    for(int n=0;n<sucker->getPrivateSize();n++) {
                        uint32_t key; cin >> key; keys[n]=key;
                    }
                    user->saveSecret(sucker, keys);
                }
                menu = HACK;
            } break;
            case VIEW_KEYS: {
                cout << "\nPublic:\n"; //first, display the public keys
                
                switch(encryptMethod) { //label the keys for clarity as to what each part does
                    case     RSA: cout << "Name: mod, power\n"; break;
                    case ELGAMAL: cout << "Name: mod, generator, h\n"; break;
                    case  CAESAR: cout << "Name: shift\n"; break;
                    case ATBASH: case NONE: cout << "Name: \n"; break;
                }
                
                for(auto it : users) {        //loop through all users
                    cout << it.first << ": "; //display their name
                    for(int n=0;n<it.second->getPublicSize();n++) { //and all their public keys
                        if(n!=0) { cout << ", "; }
                        cout << it.second->getPublic()[n];
                    }
                    cout << endl;
                }
                
                cout << "\n\nPrivate:\n"; //then, display the private keys (or at least what we think they are)
                
                for(auto it : users) {
                    if(user->hasSecret(it.second)) {
                        cout << it.first << ": ";
                        for(int n=0;n<it.second->getPrivateSize();n++) {
                            cout << user->getSecret(it.second)[n] << " ";
                        }
                        cout << "\n";
                    }
                }
                cout << "\n";
                menu = HACK;
            } break;
            case REMOVE_KEYS: {
                cout << "Whose key?\n";
                string name;
                while(true) {
                    name = requestUser(users, true,true,true);
                    if(name==user->getName()) {
                        cout << "Cannot remove your own private key. Try again\n\n";
                        continue;
                    }
                    break;
                }
                if(name!="CANCEL") {
                    user->removeSecret(users[name]);
                    cout << "Done\n";
                }
                menu = HACK;
            } break;
            case MATH: {
                cout << "\n\nMath tools available to help uncover secrets\n1. <- Go Back\n2. Prime Factor\n3. Euler's Totient\n4. Discrete Logarithm\n5. Modular Inverse\n6. Modular Exponent\n7. Modular Product\n8. GCD\n9. LCM\n\n";
                int option; cin >> option;
                switch(option) {
                    case 1: menu=HACK; break;
                    case 2: menu=FACTOR; break;
                    case 3: menu=TOTIENT; break;
                    case 4: menu=LOG; break;
                    case 5: menu=INV; break;
                    case 6: menu=POW; break;
                    case 7: menu=MUL; break;
                    case 8: menu=GCD; break;
                    case 9: menu=LCM; break;
                }
            } break;
            case FACTOR: {
                cout << "Number? (1-4294967295)\n";
                uint32_t num; cin >> num;
                cout << "Calculating...\n";
                cout << num << " = " << Discrete::factor_to_string(Discrete::primeFactor(num)) << "\n\n";
                menu = MATH;
            } break;
            case TOTIENT: {
                cout << "Number? (1-4294967295)\n";
                uint32_t num; cin >> num;
                cout << "Calculating...\n";
                cout << "phi(" << num << ")=" << Discrete::totient(num) << "\n\n";
                menu = MATH;
            } break;
            case LOG: {
                cout << "Please enter the base, number, and modulo, respectively:\n";
                uint32_t base, num, mod; cin >> base >> num >> mod;
                cout << "Calculating...\n";
                vector<uint32_t> log = Discrete::discreteLog(base,num,mod);
                if(log.empty()) { cout << "No such logarithm exists\n\n"; }
                else {
                    cout << "log_" << base << "(" << num << ") mod " << mod << " = ";
                    for(int n=0;n<log.size();n++) {
                        if(n!=0) { cout << ", "; }
                        cout << log[n];
                    }
                    cout << "\n\n";
                }
                menu = MATH;
            } break;
            case INV: {
                cout << "Please enter the number and modulo, respectively:\n";
                uint32_t num, mod; cin >> num >> mod;
                try {
                    uint32_t inv = Discrete::modInv(num,mod);
                    cout << num << "^-1 mod " << mod << " = " << inv << "\n\n";
                } catch(invalid_argument err) {
                    cout << "No such inverse exists\n\n";
                }
                menu = MATH;
            } break;
            case POW: {
                cout << "Please enter the number, power, and modulo, respectively:\n";
                uint32_t num, pow, mod; cin >> num >> pow >> mod;
                cout << num << "^" << pow << " mod " << mod << " = " << Discrete::modPow(num,pow,mod) << "\n\n";
                menu = MATH;
            } break;
            case MUL: {
                cout << "Please enter the multiplicand, multiplier, and modulo, respectively:\n";
                uint32_t m1, m2, mod; cin >> m1 >> m2 >> mod;
                cout << m1 << "*" << m2 << " mod " << mod << " = " << Discrete::modProd(m1,m2,mod) << "\n\n";
                menu = MATH;
            } break;
            case GCD: {
                cout << "Between?\n";
                uint32_t a, b; cin >> a >> b;
                cout << "gcd(" << a << "," << b << ") = " << Discrete::gcd(a,b) << "\n\n";
                menu = MATH;
            } break;
            case LCM: {
                cout << "Between?\n";
                uint32_t a, b; cin >> a >> b;
                cout << "lcm(" << a << "," << b << ") = " << Discrete::lcm(a,b) << "\n\n";
                menu = MATH;
            } break;
            case ADMIN: {
                cout << "\n\nThese aren't necessarily things that any one party would be able to do themselves, but they're helpful for the sake of editing the simulation and trying different things\n";
                cout << "1. <- Go Back\n2. Switch user\n3. Add user\n4. Remove user\n5. Change usernames\n\n";
                int option; cin >> option;
                switch(option) {
                    case 1: menu=HOME; break;
                    case 2: menu=SU; break;
                    case 3: menu=USERADD; break;
                    case 4: menu=USERDEL; break;
                    case 5: menu=USERMOD; break;
                }
            } break;
            case USERADD: {
                cout << "(Type CANCEL to go back)\nName: ";
                string name = requestUser(users, false, false, true); //request the name of the new user (cannot already exist, can cancel)
                
                if(name!="CANCEL") { //if not canceling
                    users[name] = new User(name); //create user
                    users[name]->genKey(encryptMethod); //generate them an encryption key
                }
                
                menu = ADMIN;
            } break;
            case USERDEL: {
                cout << "BE CAREFUL!\n(Type CANCEL to go back)\nName: ";
                string name;
                while(true) {
                    name = requestUser(users, true, true, true); //request name of user (user should exist, you can cancel)
                    if(name == user->getName()) { //you cannot delete yourself
                        cout << "You cannot delete yourself (though you can add another user, switch to them, and then delete the user you were before). Try again\n";
                        continue;
                    }
                    break; //but if it's not yourself, you're good to go
                }
                if(name!="CANCEL") { //if you didn't cancel
                    cout << "Are you sure you want to delete user \"" << name << "\"?\n1. Yes\n2. No\n\n";
                    int option; cin >> option;
                    if(option==1) {
                        cout << "Deleting\n";
                        
                        User* person = users[name]; //grab the person
                        for(auto it = msgList->begin(); it!=msgList->end(); ) {
                            if((**it).getSender()==person || (**it).getReceiver()==person) { msgList->erase(it); } //remove all messages to/from this user
                            else { ++it; }
                        }
                        delete person;     //delete the user
                        users.erase(name); //remove from the list
                    }
                }
                
                menu = ADMIN; //go back to admin
            } break;
            case USERMOD: {
                cout << "Current name: ";
                string iname = requestUser(users, true, true, true);
                if(iname!="CANCEL") {
                    cout << "New name: ";
                    string fname = requestUser(users, false, false, true);
                    if(fname!="CANCEL") {
                        users[iname]->setName(fname);
                        users[fname]=users[iname];
                        users.erase(iname);
                    }
                }
                menu = ADMIN;
            } break;
            case SETTINGS: {
                cout << "\nMisc settings\n1. <- Go Back\n2. Raw text mode\n3. Display private key\n\n";
                int option; cin >> option;
                switch(option) {
                    case 1: menu=HOME;      break;
                    case 2: menu=RAW_MODE;  break;
                    case 3: menu=PRIV_MODE; break;
                }
            } break;
            case RAW_MODE: {
                cout << "\nHow would you like raw, unencrypted text to be displayed?\n1. As a string\n2. As a bunch of integers\n3. As a hex dump\n";
                int option; cin >> option;
                switch(option) {
                    case 1: rawSetting=CHAR; break;
                    case 2: rawSetting=INT;  break;
                    case 3: rawSetting=HEX;  break;
                }
                menu = SETTINGS;
            } break;
            case PRIV_MODE: {
                cout << "\nWould you like to see your private key in the public key menu?\n1. Yes\n2. No\n";
                int option; cin >> option;
                privSetting = option==1;
                menu = SETTINGS;
            } break;
        }
    }
    
    return 0;
}

void allowSpaces(const bool& allow) {
    if(allow) { cin.imbue(locale(cin.getloc(), new changeDelimiter)); } //allow spaces
    else      { cin.imbue(locale(cin.getloc(), new resetDelimiter));  } //delimit spaces
}

string requestUser(map<string,User*>& users, bool canExist, bool shouldExist, bool canCancel) { ///Requests the name of a user from the cin buffer (specified is whether the user can/should exist, and whether we can cancel this dialogue)
    string name;
    while(true) {
        cin >> name;
        
        if(canCancel && name=="CANCEL") { return name; } //if we request to cancel (and are allowed to), then cancel
        if(users.contains(name) ? canExist : !shouldExist) { return name; } //if either the user exists and can exist, or doesn't exist but doesn't have to, return the name
        
        if(shouldExist) { cout << "User \"" << name << "\" doesn't exist. Please try again."; if(canCancel) { cout << " (Type CANCEL to cancel)"; } cout << "\n"; }
        else            { cout << "User \"" << name << "\" already exists. Please try again."; if(canCancel) { cout << " (Type CANCEL to cancel)"; } cout << "\n"; }
    }
}
