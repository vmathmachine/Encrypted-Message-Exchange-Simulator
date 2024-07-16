#include "Discrete.h"

Discrete::Discrete() {
    //ctor
}

Discrete::~Discrete() {
    //dtor
}

uint32_t Discrete::gcd(uint32_t a, uint32_t b) { //finds the greatest common factor between two unsigned 64-bit integers
    if(a==0 && b==0) { return 0; } //standard dictates that gcd(0,0)=0
    
    int shift = 0; //we'll multiply by 2^shift at the end
    while(((a|b)&1)==0) { a>>=1; b>>=1; ++shift; } //divide both by 2 & increment shift until at least one is odd
    
    while((b&1)==0) { b>>=1; } //If b isn't odd, make it odd
    
    while(a!=0) { //loop until a is 0
        while((a&1)==0) { a>>=1; } //If a isn't odd, make it odd
        if(a<b) { uint32_t c=a; a=b; b=c; } //make a bigger than b
        a = (a-b)>>1; //replace a w/ (a-b)/2 (making it smaller w/out changing the GCF)
    }
    //the loop is supposed to continue until one of them is 0, in which case the other is the GCF. Since a changes, a ends up being 0.
    //at the beginning of the loop, b is odd. Then a becomes odd. Then b either stays the same or becomes a (which is odd). So at the end of each iteration, b is odd.
    //hence, a can divide by 2 without needing to change the shift value
    
    return b<<shift; //return the only non-zero number, left shifted by the specified amount
}

uint64_t Discrete::lcm(uint32_t a, uint32_t b) {
    if(a==0 && b==0) { return 0; }
    return ((uint64_t)a)*b/gcd(a,b);
}

uint32_t Discrete::modProd(const uint32_t& a, const uint32_t& b, const uint32_t& c) {
    return (uint32_t)(a*(uint64_t)b % c);
}

uint32_t Discrete::modPow(uint32_t x, uint32_t p, uint32_t m) { //finds x^p % m (uses exponentiation by squaring)
    uint32_t ans=1;   //return value: x^p % m (init to 1 in case p==0)
    uint32_t exp=p;     //copy of p whose bits we can edit
    uint32_t iter=(x%m); //x ^ (2 ^ (whatever digit we're at))
    bool inits=false; //true once ans is initialized (to something other than 1)
    
    while(exp!=0) {                             //loop through all p's digits (if p==0, exit loop, return 1)
        if((exp&1)==1) {
            if(inits) { ans =modProd(ans,iter,m); } //mult ans by iter ONLY if this digit is 1
            else      { ans=iter; inits=true;      } //if ans still = 1, set ans=iter (instead of multiplying by iter)
        }
        exp >>= 1;                                     //remove the last digit
        if(exp!=0)    { iter = modProd(iter,iter,m); } //square the iterator (unless the loop is over)
    }
    
    return ans; //return the result
}

long long* Discrete::bezout(uint32_t a, uint32_t b) { //finds the solution to Bezout's identity ax+by=gcd(a,b)
    long long* prev = new long long[4] {0,a,1,0}; //two arrays, containing (in order) q, r, s, t
    long long* curr = new long long[4] {0,b,0,1};
    long long* temp; //temporary (storage) array
    
    while(curr[1]!=0) {
        prev[0]=prev[1]/curr[1]; //compute quotient
        prev[1]-=prev[0]*curr[1]; //remainder
        prev[2]-=prev[0]*curr[2]; //s
        prev[3]-=prev[0]*curr[3]; //t
        
        temp = curr; curr = prev; prev = temp; //swap temp and curr
    }
    
    //finally, return x, y, and gcd
    if(prev[1]<0) { return new long long[3] {-prev[2], -prev[3], -prev[1]}; } //if the gcd is negative, negate the result
    return                 new long long[3] { prev[2],  prev[3],  prev[1]};
}

bool Discrete::isPrimitiveRoot(uint32_t g, uint32_t m, uint32_t t) {
    std::map<uint32_t,uint32_t>* factors = primeFactor(t); //first, find all prime factors of the totient
    
    for(auto f : *factors) {
        uint32_t pow = t/f.first;
        if(modPow(g,pow,m)==1) { return false; }
    }
    return true;
}

uint32_t Discrete::makeGenerator(uint32_t p) { //generates random generator for cyclic group of prime p (p MUST BE PRIME)
    while(true) {
        uint32_t gen = rand()%(p-1)+1;
        if(isPrimitiveRoot(gen, p, p-1)) { return gen; }
    }
}

uint32_t Discrete::modInv(uint32_t x, uint32_t m) { //find the inverse of x mod m
    long long* b = bezout(x,m); //find solution to Bezout's identity
    if(b[2]!=1) { throw std::invalid_argument("Cannot take modular inverse, input and modulo must be coprime!"); } //if they aren't coprime, throw an exception
    
    uint32_t inv = (uint32_t)(b[0]>=0 ? b[0] : b[0]+m); //grab the x in Bezout's equation (make positive if needed)
    return inv;                                         //return result
}

std::vector<uint32_t> Discrete::modDiv(uint32_t a, uint32_t b, uint32_t m) { //find a / b mod m
    long long* bez = bezout(b,m); //find solution to Bezout's identity, bx+my=GCD(b,m)
    
    if(a%bez[2]!=0) {
        throw std::invalid_argument("Failed modular division");
    }
    
    uint32_t inv = (uint32_t)(bez[0]>=0 ? bez[0] : bez[0]+m); //grab the x (make positive if needed)
    uint32_t base = inv*(a/bez[2]); //find one of the solutions
    
    std::vector<uint32_t> result; //init result
    uint32_t diff = m/bez[2];
    for(int n=0;n<bez[2];n++) { //loop through all the results
        result.push_back((base+diff*n)%m); //each result is separated by a uniform distance
    }
    
    return result; //return the result
}

bool Discrete::isPrime(uint32_t x) {
    ///NOTE: there are faster primality tests, but they're all probabilistic, and I don't want to accidentally generate a composite number and break everything
    
    if(x<=1) { return false; } //if too small, return false
    auto factor = primeFactor(x); //prime factor
    if(factor->size()!=1) { return false; } //if there's more than one factor, return false
    for(auto it : *factor) { //loop through the (only) factor
        return it.second==1; //return true iff the only factor is raised to the power of 1
    }
}

uint32_t Discrete::randomPrime(uint32_t lower, uint32_t upper) { //generates random prime number in the given range
    ///NOTE: This generation is not uniform, due to the O(x/ln(x)) distribution of primes. It also never generates 2.
    if((lower&1)==0) { ++lower; } if((upper&1)==0) { --upper; } //if either are even, make odd
    uint32_t prime; do {                                        //init prime, start loop
        prime = (rand() % (upper-lower+2 >> 1) << 1) + lower; //generate random odd number in that range
    } while(!isPrime(prime));                                 //loop until prime
    return prime;                                             //return prime
}

std::map<uint32_t,uint32_t>* Discrete::primeFactor(uint32_t f) {
    std::map<uint32_t,uint32_t>* factors = new std::map<uint32_t,uint32_t>();
    
    if(f==0) { return nullptr; }
    if(f==1) { return factors; }
    
    //first, check 2, 3, 5, and 7
    uint32_t pow = 0; while((f&1)==0) { f>>=1; ++pow; }
    if(pow!=0) { (*factors)[2] = pow; }
    pow = 0; while(f%3==0) { f/=3; ++pow; }
    if(pow!=0) { (*factors)[3] = pow; }
    pow = 0; while(f%5==0) { f/=5; ++pow; }
    if(pow!=0) { (*factors)[5] = pow; }
    pow = 0; while(f%7==0) { f/=7; ++pow; }
    if(pow!=0) { (*factors)[7] = pow; }
    
    if(f==1) { return factors; } //if there are no more factors, we can stop here
    
    uint32_t root = (uint32_t)sqrt((double)f); //upper bound for factors to check
    signed char option = 2;                //something to help us avoid certain factors (namely, multiples of 2, 3, 5, or 7)
    for(uint32_t n=11;n<=root;) { //n is the number we 
        pow = 0; while(f%n==0) { f/=n; ++pow; } //count how many times f is divisible by n
        if(pow!=0) { //if non-zero:
            (*factors)[n] = pow; //attach to our prime factorization
            root = (uint32_t)sqrt((double)f); //recalculate our upper bound (it should be much lower now)
        }
        
        //now, our next value for n depends on our option:
        switch(option&127) { //switch the option (ignore the signed bit)
            case  0: n+=2; option^=-128; break; //for option  0, we increase by 2 and switch directions
            case 24: n+=4; option^=-128; break; //for option 24, we increase by 4 and switch directions
            
            case 2: case 4: case  7: case 10: case 14: case 17: case 23: n+=2; break; //for these options, increase by 2
            case 3: case 5: case  9: case 11: case 16: case 19: case 22: n+=4; break; //for these options, increase by 4
            case 6: case 8: case 12: case 13: case 15: case 18: case 20: n+=6; break; //for these options, increase by 6
            
            case 21: n+= 8; break; //increase by 8
            case  1: n+=10; break; //increase by 10
        }
        if(option<0) { option--; } else { option++; } //If negative, decrease. If positive, increase
        
        /**Explanation of the above code:
        
        The naive method of factoring a number is to loop through all numbers and divide by whichever ones we can. This can be improved by only looping through numbers
        less than or equal to the square root, turning it from O(n) to O(n^(1/2)). Beyond that, you can also cut out all even numbers excluding 2, as non-2 primes can only be
        odd. This cuts the time in half. Continuing from there, you can also cut out all multiples of 3, and only check numbers 1 greater or 1 less than a multiple of 6.
        You can also cut out multiples of 5, thus only choosing numbers that are certain numbers modulo 2*3*5=30. If you add 7 to the mix, you're only choosing numbers that are certain
        numbers modulo 210. That's what the above code does. It takes all numbers 0-209 and only allows n mod 210 to be one of the 48 numbers in that range that aren't divisible by 2, 3, 5, or 7.
        "option" enumerates which of those 48 values n is modulo 210. Depending on which option you have, n might have to jump by 2 (twin prime), 4, 6, 8, or 10 to reach the next value of n.
        
        Intuitively, option should be n%210, and that would work as well, but I originally wrote the above code in java, where 8-bit numbers are always signed, so I just had option be a number 0-48.
        Except not really, because the first 24 values are just 210 minus the last 24 values, so I took advantage of the symmetry and made it so, once you hit option 24, the option starts decreasing,
        and when you hit option 0 again, the option starts increasing again. The sign bit enumerates which direction to move in. So, as a result, there's 25 cases (25 because of the fence post
        problem).
        
        It should be noted that this can also be made more efficient by cutting out multiples of 11, 13, 17, etc. However, doing this causes the amount of individual cases to increase exponentially,
        all while yielding diminishing returns in terms of efficiency. Cutting out evens results in only looking at 50% of numbers and only looking at 1 case, cutting out multiples of 3 as well brings
        that down to 33.3% and creates 2 cases, then 5 brings that to 26.7% but 8 cases (5 cases with symmetry), then 7 (what we have now) makes 22.9% but 48 cases (25 w/ symmetry). 11 makes 20.8% but
        241 cases, 13 makes 19.2% but 2881 cases, 17 makes 18.1% and 46081 cases, etc. 
        
        **/
    }
    
    if(f!=1) { (*factors)[f] = 1; } //by the end of the loop, all that's left should be the biggest prime factor, append that to the prime factorization
    //the exception to this rule is if the largest prime factor has a power greater than 1, in which case it will have already been factored out and all we'll have left is 1
    
    return factors; //return our prime factorization
}

uint32_t Discrete::totient(uint32_t x) { //compute euler's totient function
    std::map<uint32_t, uint32_t>* factors = primeFactor(x); //take prime factorization
    
    for(auto it : *factors) { //loop through all prime factors
        x -= x/it.first;     //multiply x by (1-1/p)
    }
    return x;
}

std::string Discrete::factor_to_string(std::map<uint32_t,uint32_t>* factors) {
    if(factors==nullptr) { return "0"; }
    if(factors->empty()) { return "Empty Product"; }
    std::stringstream stream;
    bool init = false;
    for(auto it : *factors) {
        if(init) { stream << "*"; }
        stream << it.first;
        if(it.second!=1) { stream << "^" << it.second; }
        init = true;
    }
    return stream.str();
}

/*void Discrete::pollardRhoProgress(uint32_t* xab, const uint32_t& alpha, const uint32_t& beta, const uint32_t& n) {
    switch(xab[0]%3) {
        case 0: xab[0] = xab[0]*xab[0]%n; xab[1] = (xab[1]<<1)%(n-1); xab[2] = (xab[2]<<1)%(n-1); break;
        case 1: xab[0] = xab[0]*alpha%n; xab[1] = (xab[1]+1)%(n-1); break;
        case 2: xab[0] = xab[0]*beta%n; xab[2] = (xab[2]+1)%(n-1); break;
    }
}

std::vector<uint32_t> Discrete::discreteLog(uint32_t alpha, uint32_t beta, uint32_t m) { //computes the discrete logarithm using Pollard's rho algorithm
    uint32_t* xab1 = new uint32_t[3] {1,0,0};
    uint32_t* xab2 = new uint32_t[3] {1,0,0};
    for(int i=0;i<m-1;i++) {
        pollardRhoProgress(xab1,alpha,beta,m);
        pollardRhoProgress(xab2,alpha,beta,m);
        pollardRhoProgress(xab2,alpha,beta,m);
        if(xab1[0]==xab2[0]) { break; }
    }
    //alpha^a1*beta^b1 = alpha^a2*beta^b2 = x
    //beta = alpha^y, a1+b1*y = a2+b2*y, a1-a2 = (b2-b1)*y
    try { return modDiv(xab1[1]-xab2[1],xab2[2]-xab1[2],m-1); }
    catch(std::invalid_argument a) { std::vector<uint32_t> result; return result; }
}*/

///INITIALLY, the discrete logarithm was computed via Pollard's rho algorithm (O(m^(1/2)), but that didn't work for some reason, so I'm instead just switching to brute force (O(m))
std::vector<uint32_t> Discrete::discreteLog(uint32_t a, uint32_t b, uint32_t m) { //computes the discrete logarithm using brute force
    std::vector<uint32_t> result;
    uint32_t pow = 1;
    for(int n=0;n<m-1;n++) {
        if(pow==b) { result.push_back(n); }
        pow = modProd(pow, a, m);
    }
    return result;
}

uint32_t Discrete::stringHash(const std::string& s) {
    uint32_t hash = 0;
    for(int n=0; s[n]!='\0'; n++) {
        hash = 31*hash + s[n];
    }
    return hash;
}
