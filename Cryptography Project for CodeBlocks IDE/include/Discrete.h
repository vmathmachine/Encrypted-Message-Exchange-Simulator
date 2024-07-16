#ifndef DISCRETE_H
#define DISCRETE_H

#include <cstdint>
#include <cmath>
#include <map>
#include <stdexcept>
#include <sstream>
#include <vector>


class Discrete { //a static class that holds a bunch of useful modular arithmetic functions
    //A lot of these are functions that I wrote either before this class (e.g. exponentiation by squaring), or during this class out of interest (e.g. modular inverse)
    public:
        Discrete();
        virtual ~Discrete();
        
        static uint32_t gcd(uint32_t a, uint32_t b); //greatest common factor
        static uint64_t lcm(uint32_t a, uint32_t b); //least common multiple
        
        static uint32_t modProd(const uint32_t& a, const uint32_t& b, const uint32_t& m); //a*b mod m
        
        static long long* bezout(uint32_t a, uint32_t b); //solves bezout's identity ax+by=gcd(a,b)
        static uint32_t modInv(uint32_t x, uint32_t m); //finds the modular inverse of x mod m
        static uint32_t modPow(uint32_t x, uint32_t p, uint32_t m); //finds x raised to the power of p mod m
        
        static std::vector<uint32_t> modDiv(uint32_t a, uint32_t b, uint32_t m); //finds a / b mod m (may be multiple answers, or no answers at all)
        
        static bool isPrime(uint32_t x); //returns whether the given number is prime
        static uint32_t randomPrime(uint32_t lower, uint32_t upper); //finds a random prime in the given range (will loop forever if there are none)
        
        static bool isPrimitiveRoot(uint32_t g, uint32_t m, uint32_t t); //returns whether g is a primitive root of m (whose totient is t)
        static uint32_t makeGenerator(uint32_t p); //randomly generates a generator for prime p
        
        ///HACKING TOOLS///
        static std::map<uint32_t,uint32_t>* primeFactor(uint32_t f); //finds prime factorization (expressed as a map from factors to exponents)
        static uint32_t totient(uint32_t x); //returns the Euler's totient function of the input
        static std::vector<uint32_t> discreteLog(uint32_t a, uint32_t b, uint32_t m); //finds the discrete base a logarithm of b, mod m
        
        static std::string factor_to_string(std::map<uint32_t,uint32_t>* factors);
        
        static uint32_t stringHash(const std::string& s);
    protected:
        
    private:
        
        static void pollardRhoProgress(uint32_t* xab, const uint32_t& a, const uint32_t& b, const uint32_t& n);
};

/*
modular power
modular inverse
GCF
LCM

Prime factor
Is prime
totient

*/

#endif // DISCRETE_H
