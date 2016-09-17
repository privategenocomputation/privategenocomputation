#include <algorithm>
#include <stdexcept>
#include <cmath>
#include "Decryptor_k.h"
#include "util/common.h"
#include "util/uintcore.h"
#include "util/uintarith.h"
#include "util/polycore.h"
#include "util/polyarith.h"
#include "util/polyarithmod.h"
#include "util/clipnormal.h"
#include "util/randomtostd.h"
#include "bigpolyarith.h"
#include "bigpoly.h"
#include "biguint.h"
#include "util/uintarithmod.h"
#include "util/polyextras.h"
#include "polycrt.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    namespace
    {
        bool are_poly_coefficients_less_than(const BigPoly &poly, const BigUInt &max_coeff)
        {
            return util::are_poly_coefficients_less_than(poly.pointer(), poly.coeff_count(), poly.coeff_uint64_count(), max_coeff.pointer(), max_coeff.uint64_count());
        }
    }
    
    Decryptor_k::Decryptor_k(const EncryptionParameters &parms, const BigPoly &secret_key) :
    poly_modulus_(parms.poly_modulus()), coeff_modulus_(parms.coeff_modulus()), plain_modulus_(parms.plain_modulus()), secret_key_(secret_key), orig_plain_modulus_bit_count_(parms.plain_modulus().significant_bit_count())
    {
        // Verify required parameters are non-zero and non-nullptr.
        if (poly_modulus_.is_zero())
        {
            throw invalid_argument("poly_modulus cannot be zero");
        }
        if (coeff_modulus_.is_zero())
        {
            throw invalid_argument("coeff_modulus cannot be zero");
        }
        if (plain_modulus_.is_zero())
        {
            throw invalid_argument("plain_modulus cannot be zero");
        }
        
        if (secret_key_.is_zero())
        {
            throw invalid_argument("secret_key cannot be zero");
        }
        
        // Verify parameters.
        if (plain_modulus_ >= coeff_modulus_)
        {
            throw invalid_argument("plain_modulus must be smaller than coeff_modulus");
        }
        if (!are_poly_coefficients_less_than(poly_modulus_, coeff_modulus_))
        {
            throw invalid_argument("poly_modulus cannot have coefficients larger than coeff_modulus");
        }
        
        // Resize encryption parameters to consistent size.
        int coeff_count = poly_modulus_.significant_coeff_count();
        int coeff_bit_count = coeff_modulus_.significant_bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
        if (poly_modulus_.coeff_count() != coeff_count || poly_modulus_.coeff_bit_count() != coeff_bit_count)
        {
            poly_modulus_.resize(coeff_count, coeff_bit_count);
        }
        if (coeff_modulus_.bit_count() != coeff_bit_count)
        {
            coeff_modulus_.resize(coeff_bit_count);
        }
        if (plain_modulus_.bit_count() != coeff_bit_count)
        {
            plain_modulus_.resize(coeff_bit_count);
        }
        if (secret_key_.coeff_count() != coeff_count || secret_key_.coeff_bit_count() != coeff_bit_count ||
            secret_key_.significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(secret_key_, coeff_modulus_))
        {
            throw invalid_argument("secret_key is not valid for encryption parameters");
        }
        
        // Set the secret_key_array to have size 1 (first power of secret)
        secret_key_array_.resize(1, coeff_count, coeff_bit_count);
        set_poly_poly(secret_key_.pointer(), coeff_count, coeff_uint64_count, secret_key_array_.pointer(0));
        
        MemoryPool &pool = *MemoryPool::default_pool();
        
        // Calculate coeff_modulus / plain_modulus.
        coeff_div_plain_modulus_.resize(coeff_bit_count);
        Pointer temp(allocate_uint(coeff_uint64_count, pool));
        divide_uint_uint(coeff_modulus_.pointer(), plain_modulus_.pointer(), coeff_uint64_count, coeff_div_plain_modulus_.pointer(), temp.get(), pool);
        
        // Calculate coeff_modulus / plain_modulus / 2.
        coeff_div_plain_modulus_div_two_.resize(coeff_bit_count);
        right_shift_uint(coeff_div_plain_modulus_.pointer(), 1, coeff_uint64_count, coeff_div_plain_modulus_div_two_.pointer());
        
        // Calculate coeff_modulus / 2.
        upper_half_threshold_.resize(coeff_bit_count);
        half_round_up_uint(coeff_modulus_.pointer(), coeff_uint64_count, upper_half_threshold_.pointer());
        
        // Calculate upper_half_increment.
        upper_half_increment_.resize(coeff_bit_count);
        multiply_truncate_uint_uint(plain_modulus_.pointer(), coeff_div_plain_modulus_.pointer(), coeff_uint64_count, upper_half_increment_.pointer());
        sub_uint_uint(coeff_modulus_.pointer(), upper_half_increment_.pointer(), coeff_uint64_count, upper_half_increment_.pointer());
        
        // Initialize moduli.
        polymod_ = PolyModulus(poly_modulus_.pointer(), coeff_count, coeff_uint64_count);
        mod_ = Modulus(coeff_modulus_.pointer(), coeff_uint64_count, pool);
    }
    
    void Decryptor_k::decryptSPU(BigPolyArray &encrypted, BigPoly &destination)
    {
        // Extract encryption parameters.
        // Remark: poly_modulus_ has enlarged coefficient size set in constructor
        int coeff_count = poly_modulus_.coeff_count();
        int coeff_bit_count = poly_modulus_.coeff_bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
        
        // Verify parameters.
        if (encrypted.size() < 2 || encrypted.coeff_count() != coeff_count || encrypted.coeff_bit_count() != coeff_bit_count)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        
#ifdef _DEBUG
        for (int i = 0; i < encrypted.size(); ++i)
        {
            if (encrypted[i].significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(encrypted[i], coeff_modulus_))
            {
                throw invalid_argument("encrypted is not valid for encryption parameters");
            }
        }
#endif
        
        // Make sure destination is of right size to perform all computations. At the end we will
        // resize the coefficients to be the size of plain_modulus.
        // Remark: plain_modulus_ has enlarged coefficient size set in constructor
        if (destination.coeff_count() != coeff_count || destination.coeff_bit_count() != coeff_bit_count)
        {
            destination.resize(coeff_count, coeff_bit_count);
        }
        
        MemoryPool &pool = *MemoryPool::default_pool();
        
        // Make sure we have enough secret keys computed
        compute_secret_key_array(encrypted.size() - 1);
        
        cout<<"normal noise added"<<endl;
        
        /*
         Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
         This is equal to Delta m + v where ||v|| < Delta/2.
         So, add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
         Therefore, we can (integer) divide by Delta and the answer will round down to m.
         */
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        dot_product_bigpolyarray_polymod_coeffmod(encrypted.pointer(1), secret_key_array_.pointer(0), encrypted.size() - 1, polymod_, mod_, destination.pointer(), pool);
        //add_poly_poly_coeffmod(destination.pointer(), encrypted[1].pointer(), coeff_count, coeff_modulus_.pointer(), coeff_uint64_count, destination.pointer());
        MemoryPool &poolforrSPU = *MemoryPool::default_pool();
        //unique_ptr<UniformRandomGenerator> random(parms.random_generator()->create());
        //Pointer error(allocate_poly(coeff_count, coeff_uint64_count, pool));
        BigPoly desBeforNoise=destination;
        
        BigPoly errorSPU(coeff_count, coeff_bit_count);
        errorSPU.set_zero();
        unique_ptr<UniformRandomGenerator> randomSPU(UniformRandomGeneratorFactory::default_factory()->create());
        Pointer tempSPU(allocate_poly(coeff_count, coeff_uint64_count, poolforrSPU));
        set_poly_coeffs_normal(tempSPU.get(), randomSPU.get());
        add_poly_poly_coeffmod(tempSPU.get(), errorSPU.pointer(), coeff_count, mod_.get(), coeff_uint64_count, errorSPU.pointer());
        add_poly_poly_coeffmod(destination.pointer(), errorSPU.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination.pointer());
        BigPoly desAfterNoise=destination;
        
        if (desBeforNoise.to_string()!=desAfterNoise.to_string()) {
            cout<<"noise added in SPU partial decryption"<<endl;
        }
    }
    
    void Decryptor_k::decryptMU(BigPolyArray &encrypted, BigPolyArray & plaintext_slot_noise, BigPoly &destination, BigPoly &cpSPU, BigPolyArray &secret_key_MU_array, int vector_size)
    {
        
        // Extract encryption parameters.
        // Remark: poly_modulus_ has enlarged coefficient size set in constructor
        int coeff_count = poly_modulus_.coeff_count();
        int coeff_bit_count = poly_modulus_.coeff_bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
        
        // Verify parameters.
        if (encrypted.size() < 2 || encrypted.coeff_count() != coeff_count || encrypted.coeff_bit_count() != coeff_bit_count)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        
#ifdef _DEBUG
        for (int i = 0; i < encrypted.size(); ++i)
        {
            if (encrypted[i].significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(encrypted[i], coeff_modulus_))
            {
                throw invalid_argument("encrypted is not valid for encryption parameters");
            }
        }
#endif
        
        // Verify parameters.
        if (plaintext_slot_noise.size() < 2 || plaintext_slot_noise.coeff_count() != coeff_count || plaintext_slot_noise.coeff_bit_count() != coeff_bit_count)
        {
            throw invalid_argument("plaintext_slot_noise is not valid for encryption parameters");
        }
        
#ifdef _DEBUG
        for (int i = 0; i < plaintext_slot_noise.size(); ++i)
        {
            if (plaintext_slot_noise[i].significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(plaintext_slot_noise[i], coeff_modulus_))
            {
                throw invalid_argument("plaintext_slot_noise is not valid for encryption parameters");
            }
        }
#endif
        
        // Make sure destination is of right size to perform all computations. At the end we will
        // resize the coefficients to be the size of plain_modulus.
        // Remark: plain_modulus_ has enlarged coefficient size set in constructor
        
        MemoryPool &pool = *MemoryPool::default_pool();
        
        
        // Make sure we have enough secret keys computed
        compute_secret_key_array(encrypted.size() - 1);
        
        /*
         Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
         This is equal to Delta m + v where ||v|| < Delta/2.
         So, add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
         Therefore, we can (integer) divide by Delta and the answer will round down to m.
         */
        
        if (destination.coeff_count() != coeff_count || destination.coeff_bit_count() != coeff_bit_count)
        {
            destination.resize(coeff_count, coeff_bit_count);
        }
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        BigPolyArray secret_key_SPU_array;
        secret_key_SPU_array.resize(secret_key_array_.size(), coeff_count, coeff_bit_count);
        BigPolyArith bpa;
        cout<<"secret_key_array_.size is: "<<secret_key_array_.size()<<"secret_key_MU_array.size is: "<<secret_key_MU_array.size()<<endl;
        cout<<"coeff_count is:"<<coeff_count<<endl;
        cout<<"coeff_uint64_count is:"<<coeff_uint64_count<<endl;
        for (int i=0; i<secret_key_array_.size(); i++) {
            sub_poly_poly_coeffmod(secret_key_array_.pointer(i), secret_key_MU_array.pointer(i), coeff_count, coeff_modulus_.pointer(), coeff_uint64_count, secret_key_SPU_array.pointer(i));
        }
        cout<<"000"<<endl;

        
        
        ////////////////////////////////////
        //For the testing of correct splitting of the secret keys
        ////////////////////////////////////
        
        BigPolyArray t;
        t.resize(secret_key_array_.size(), coeff_count, coeff_bit_count);
        for (int i=0; i<secret_key_array_.size(); i++) {
            add_poly_poly_coeffmod(secret_key_MU_array.pointer(i), secret_key_SPU_array.pointer(i), coeff_count, mod_.get(), coeff_uint64_count, t.pointer(i));
            if (t[i]!=secret_key_array_[i]) {
                cout<<"key split incorrectly"<<endl;
            }
            
        }
        
        /*
        dot_product_bigpolyarray_polymod_coeffmod(encrypted.pointer(1), t.pointer(0), encrypted.size() - 1, polymod_, mod_, destination.pointer(), pooldotproduct1);
        
        add_poly_poly_coeffmod(destination.pointer(), encrypted[0].pointer(), coeff_count, coeff_modulus_.pointer(), coeff_uint64_count, destination.pointer());
        */
        
        cout<<"encrypted.size is: "<<encrypted.size()<<endl;
        dot_product_bigpolyarray_polymod_coeffmod(encrypted.pointer(1), secret_key_array_.pointer(0), 1, polymod_, mod_, destination.pointer(), pool);
        
        //add_poly_poly_coeffmod(destination.pointer(), encrypted[0].pointer(), coeff_count, coeff_modulus_.pointer(), coeff_uint64_count, destination.pointer());
        /*
        Pointer temp2(allocate_poly(coeff_count, coeff_uint64_count, pool));
        multiply_poly_poly_polymod_coeffmod(encrypted[1].pointer(), secret_key_array_[0].pointer(), polymod_, mod_, temp2.get(), pool);
        add_poly_poly_coeffmod(destination.pointer(), temp2.get(), coeff_count, mod_.get(), coeff_uint64_count, destination.pointer());*/
        
        ////////////////////////////////////
        //For the testing of correct splitting of the secret keys
        ////////////////////////////////////

        BigPoly destination1;
        
        if (destination1.coeff_count() != coeff_count || destination1.coeff_bit_count() != coeff_bit_count)
        {
            destination1.resize(coeff_count, coeff_bit_count);
        }
        
        add_poly_poly_coeffmod(secret_key_MU_array[0].pointer(), secret_key_SPU_array[0].pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination1.pointer());
        if (secret_key_array_[0]==destination1) {
            cout<<"key split correctly"<<endl;
        }
        ////////////////////////////////////
        //For addition and substraction and negation
        ////////////////////////////////////
        
        
        cout<<"1111"<<endl;
        BigPoly destination2;
        
        if (destination2.coeff_count() != coeff_count || destination2.coeff_bit_count() != coeff_bit_count)
        {
            destination2.resize(coeff_count, coeff_bit_count);
        }
        BigPoly temp3;
        
        if (temp3.coeff_count() != coeff_count || temp3.coeff_bit_count() != coeff_bit_count)
        {
            temp3.resize(coeff_count, coeff_bit_count);
        }
        /*
        Pointer temp3(allocate_poly(coeff_count, coeff_uint64_count, pool));
        cout<<"multiplication for first multiplication then addition"<<endl;*/
        dot_product_bigpolyarray_polymod_coeffmod(encrypted.pointer(1), secret_key_MU_array.pointer(0), 1, polymod_, mod_, temp3.pointer(), pool);
        BigPoly tp3=temp3;
        for (int i=0; i<vector_size; i++) {
            temp3=tp3;
            polyPermutate(temp3, 2*i+1, poly_modulus_.coeff_count()-1);
            add_poly_poly_coeffmod(destination2.pointer(), temp3.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination2.pointer());
        }
        
        //add_poly_poly_coeffmod(destination2.pointer(), temp3.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination2.pointer());
        /*Pointer temp4(allocate_poly(coeff_count, coeff_uint64_count, pool));*/
        BigPoly temp4;
        
        if (temp4.coeff_count() != coeff_count || temp4.coeff_bit_count() != coeff_bit_count)
        {
            temp4.resize(coeff_count, coeff_bit_count);
        }
        dot_product_bigpolyarray_polymod_coeffmod(encrypted.pointer(1), secret_key_SPU_array.pointer(0), 1, polymod_, mod_, temp4.pointer(), pool);
        BigPoly tp4=temp4;
        for (int i=0; i<vector_size; i++) {
            temp4=tp4;
            polyPermutate(temp4, 2*i+1, poly_modulus_.coeff_count()-1);
            add_poly_poly_coeffmod(destination2.pointer(), temp4.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination2.pointer());
        }
        
        
        ////////////////////////////////////
        //For testing of dot product correctness for addition and substraction
        ////////////////////////////////////
        if (destination==destination2) {
            cout<<"dot product correct"<<endl;
        }
        
        ////////////////////////////////////
        //The final step for threshold version.
        ////////////////////////////////////
        
    
        if (destination==destination2) {
            cout<<"dot product correct"<<endl;
        }
        BigPoly temp0;
        
        if (temp0.coeff_count() != coeff_count || temp0.coeff_bit_count() != coeff_bit_count)
        {
            temp0.resize(coeff_count, coeff_bit_count);
        }
        BigPoly e0=encrypted[0];
        for (int i=0; i<vector_size; i++) {
            temp0=e0;
            polyPermutate(temp0, 2*i+1, poly_modulus_.coeff_count()-1);
            add_poly_poly_coeffmod(destination2.pointer(), temp0.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination2.pointer());
        }
        
        ////////////////////////////////////
        //Generating and Adding plaintext slot noise to the decrypted polynomial
        ////////////////////////////////////
        
            ////////////////////////////////////
            //Generating plaintext slot noise to the decrypted polynomial
            ////////////////////////////////////
        
        BigPoly destination3;
        
        if (destination3.coeff_count() != coeff_count || destination3.coeff_bit_count() != coeff_bit_count)
        {
            destination3.resize(coeff_count, coeff_bit_count);
        }
        BigPoly temp5;
        
        if (temp5.coeff_count() != coeff_count || temp5.coeff_bit_count() != coeff_bit_count)
        {
            temp5.resize(coeff_count, coeff_bit_count);
        }
        
        dot_product_bigpolyarray_polymod_coeffmod(plaintext_slot_noise.pointer(1), secret_key_MU_array.pointer(0), 1, polymod_, mod_, temp5.pointer(), pool);
        
        BigPoly temp6;
        
        if (temp6.coeff_count() != coeff_count || temp6.coeff_bit_count() != coeff_bit_count)
        {
            temp6.resize(coeff_count, coeff_bit_count);
        }
        dot_product_bigpolyarray_polymod_coeffmod(plaintext_slot_noise.pointer(1), secret_key_SPU_array.pointer(0), 1, polymod_, mod_, temp6.pointer(), pool);
        add_poly_poly_coeffmod(destination3.pointer(), temp5.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination3.pointer());
        add_poly_poly_coeffmod(destination3.pointer(), temp6.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination3.pointer());
        add_poly_poly_coeffmod(destination3.pointer(), plaintext_slot_noise.pointer(0), coeff_count, mod_.get(), coeff_uint64_count, destination3.pointer());
            ////////////////////////////////////
            //adding plaintext slot noise to the decrypted polynomial
            ////////////////////////////////////
        add_poly_poly_coeffmod(destination2.pointer(), destination3.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination2.pointer());
        
        ////////////////////////////////////
        //Generate random noise to mask all the plaintext slots other than the first one.
        ////////////////////////////////////
        /*
        BigPoly destination3;
        
        if (destination3.coeff_count() != coeff_count || destination3.coeff_bit_count() != coeff_bit_count)
        {
            destination3.resize(coeff_count, coeff_bit_count);
        }
        PolyCRTBuilder crtbuilder(plain_modulus_, poly_modulus_);
        size_t slot_count = crtbuilder.get_slot_count();
        
        // Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
        vector<BigUInt> values1(slot_count, BigUInt(14, static_cast<uint64_t>(0)));
        cout<<"parms.plain_modulus is: "<<plain_modulus_.to_string()<<"parms.poly_modulus is: "<<poly_modulus_.to_string()<<endl;
        cout<<"slot_count is: "<<slot_count<<endl;
        cout<<"parms.plain_modulus().bit_count() is: "<<plain_modulus_.bit_count()<<endl;
        int vector_size=3;
        // Set the first few entries of the values vector to be non-zero
        values1[0]=0;
        for (int i=1; i<vector_size; i++) {
            values1[i]=4;
            //values1[i]=rand()%(plain_modulus_);
        }
        // Now compose these into one polynomial using PolyCRTBuilder
        
        BigPoly plain_composed_noise;
        if (plain_composed_noise.coeff_count() != coeff_count || plain_composed_noise.coeff_bit_count() != coeff_bit_count)
        {
            plain_composed_noise.resize(coeff_count, coeff_bit_count);
        }
        cout<<"2222"<<endl;
        plain_composed_noise = crtbuilder.compose(values1);
        cout<<"3333"<<endl;
        //polyPermutate(encrypted[0], 1, poly_modulus_.coeff_count()-1);
        add_poly_poly_coeffmod(destination3.pointer(), plain_composed_noise.pointer(), coeff_count, coeff_modulus_.pointer(), coeff_uint64_count, destination3.pointer());*/
        
        destination=destination2;
        
        cout<<"the degree of the poly_modulus is: "<<poly_modulus_.coeff_count()-1<<endl;
        
        ////////////////////////////////////
        //Add noise to mask the result.
        ////////////////////////////////////
        /*
        MemoryPool &poolforrMU = *MemoryPool::default_pool();
        BigPoly errorMU(coeff_count, coeff_bit_count);
        errorMU.set_zero();
        unique_ptr<UniformRandomGenerator> randomMU(UniformRandomGeneratorFactory::default_factory()->create());
        Pointer tempMU(allocate_poly(coeff_count, coeff_uint64_count, poolforrMU));
        set_poly_coeffs_normal(tempMU.get(), randomMU.get());
        add_poly_poly_coeffmod(tempMU.get(), errorMU.pointer(), coeff_count, mod_.get(), coeff_uint64_count, errorMU.pointer());
        add_poly_poly_coeffmod(destination.pointer(), errorMU.pointer(), coeff_count, mod_.get(), coeff_uint64_count, destination.pointer());*/
        
        ////////////////////////////////////
        //Permutate the resultant polynomial for the permutation of the plaintext slots.
        ////////////////////////////////////
        
        //cout<<"original polynomial is: "<<destination2.to_string()<<endl;
        //polyPermutate(destination, 5, poly_modulus_.coeff_count()-1);
        //cout<<"new polynomial after permutation is: "<<destination.to_string()<<endl;
        if (destination==destination2) {
            cout<<"polynomial computed correctly"<<endl;
        }
        
        
        // For each coefficient, reposition and divide by coeff_div_plain_modulus.
        uint64_t *dest_coeff = destination.pointer();
        Pointer quotient(allocate_uint(coeff_uint64_count, pool));
        Pointer big_alloc(allocate_uint(2 * coeff_uint64_count, pool));
        for (int i = 0; i < coeff_count; ++i)
        {
            // Round to closest level by adding coeff_div_plain_modulus_div_two (mod coeff_modulus).
            add_uint_uint_mod(dest_coeff, coeff_div_plain_modulus_div_two_.pointer(), coeff_modulus_.pointer(), coeff_uint64_count, dest_coeff);
            
            // Reposition if it is in upper-half of coeff_modulus.
            bool is_upper_half = is_greater_than_or_equal_uint_uint(dest_coeff, upper_half_threshold_.pointer(), coeff_uint64_count);
            if (is_upper_half)
            {
                sub_uint_uint(dest_coeff, upper_half_increment_.pointer(), coeff_uint64_count, dest_coeff);
            }
            
            // Find closest level.
            divide_uint_uint_inplace(dest_coeff, coeff_div_plain_modulus_.pointer(), coeff_uint64_count, quotient.get(), pool, big_alloc.get());
            set_uint_uint(quotient.get(), coeff_uint64_count, dest_coeff);
            dest_coeff += coeff_uint64_count;
        }
        
        // Resize the coefficient to the original plain_modulus size
        destination.resize(coeff_count, orig_plain_modulus_bit_count_);
        cout<<"decryption combine donedecryption combine donedecryption combine done"<<endl;
    }
    
    void Decryptor_k::polyPermutate(BigPoly& inp, int exponent, int poly_mod)
    {
        BigPoly res=inp;
        
        int coeff_count = poly_modulus_.coeff_count();
        //cout<<"coeff_count is: "<<coeff_count<<endl;
        int coeff_bit_count = poly_modulus_.coeff_bit_count();
        /*if (res.coeff_count() != coeff_count || res.coeff_bit_count() != coeff_bit_count)
        {
            res.resize(coeff_count, coeff_bit_count);
        }*/
        
        int *power = new int[coeff_count-1];
        int *tmp = new int[coeff_count-1];
        for (int i=0; i<coeff_count-1; i++) {
            int tmp2=(i*exponent)%poly_mod;
            tmp[i]=(i*exponent/poly_mod)%2;
            power[tmp2]=i;
        }
        /*
        for (int i=0; i<coeff_count-1; i++) {
            res.operator[](i)=inp.operator[](power[i]).operator*(sign[power[i]]);
        }*/
        for (int i=0; i<coeff_count-1; i++) {
            BigUInt t;
            t.set_zero();
            //cout<<"inp["<<i<<"]"<<inp[i].to_string()<<endl;
            if (tmp[power[i]]) {
                res[i]=t.operator-(inp[power[i]]);
            }
            else {
                res[i]=t.operator+(inp[power[i]]);
            }
            //cout<<"res["<<i<<"]"<<res[i].to_string()<<endl;
        }
        inp=res;
        return;
    }
    
    void Decryptor_k::compute_secret_key_array(int max_power)
    {
        if (max_power < 1)
        {
            throw invalid_argument("max_power cannot be less than 1");
        }
        
        int old_count = secret_key_array_.size();
        int new_count = max(max_power, secret_key_array_.size());
        
        if (old_count == new_count)
        {
            return;
        }
        
        int coeff_count = poly_modulus_.coeff_count();
        int coeff_bit_count = coeff_modulus_.bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
        
        // Compute powers of secret key until max_power
        secret_key_array_.resize(new_count, coeff_count, coeff_bit_count);
        
        MemoryPool &pool = *MemoryPool::default_pool();
        
        int poly_ptr_increment = coeff_count * coeff_uint64_count;
        uint64_t *prev_poly_ptr = secret_key_array_.pointer(old_count - 1);
        uint64_t *next_poly_ptr = prev_poly_ptr + poly_ptr_increment;
        for (int i = old_count; i < new_count; ++i)
        {
            multiply_poly_poly_polymod_coeffmod(prev_poly_ptr, secret_key_.pointer(), polymod_, mod_, next_poly_ptr, pool);
            prev_poly_ptr = next_poly_ptr;
            next_poly_ptr += poly_ptr_increment;
        }
    }
    
    void Decryptor_k::set_poly_coeffs_normal(std::uint64_t *poly, UniformRandomGenerator *random) const
    {
        int coeff_count = poly_modulus_.coeff_count();
        int coeff_bit_count = poly_modulus_.coeff_bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
        if (noise_standard_deviation_ == 0 || noise_max_deviation_ == 0)
        {
            set_zero_poly(coeff_count, coeff_uint64_count, poly);
            return;
        }
        RandomToStandardAdapter engine(random);
        ClippedNormalDistribution dist(0, noise_standard_deviation_, noise_max_deviation_);
        for (int i = 0; i < coeff_count - 1; ++i)
        {
            int64_t noise = static_cast<int64_t>(dist(engine));
            if (noise > 0)
            {
                set_uint(static_cast<uint64_t>(noise), coeff_uint64_count, poly);
            }
            else if (noise < 0)
            {
                noise = -noise;
                set_uint(static_cast<uint64_t>(noise), coeff_uint64_count, poly);
                sub_uint_uint(coeff_modulus_.pointer(), poly, coeff_uint64_count, poly);
            }
            else
            {
                set_zero_uint(coeff_uint64_count, poly);
            }
            poly += coeff_uint64_count;
        }
        set_zero_uint(coeff_uint64_count, poly);
    }
}