#include <algorithm>
#include <stdexcept>
#include "decryptor.h"
#include "util/common.h"
#include "util/uintcore.h"
#include "util/uintarith.h"
#include "util/polycore.h"
#include "util/polyarith.h"
#include "util/polyarithmod.h"
#include "bigpoly.h"
#include "util/uintarithmod.h"
#include "util/polyextras.h"

#include <iostream>

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

    void Decryptor::lastStep(const BigPoly &encrypted, BigPoly &destination)
    {
std::cout << "lastStep\n";
//std::cout << "myPoly" << encrypted.to_string() << std::endl;
        // Extract encryption parameters.
        // Remark: poly_modulus_ has enlarged coefficient size set in constructor
        int coeff_count = poly_modulus_.coeff_count();
        int coeff_bit_count = poly_modulus_.coeff_bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);

        // Verify parameters.
        if (encrypted.coeff_count() != coeff_count || encrypted.coeff_bit_count() != coeff_bit_count)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
#ifdef _DEBUG
        if (encrypted.significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(encrypted, coeff_modulus_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
#endif
        // Make sure destination is of right size to perform all computations. At the end we will
        // resize the coefficients to be the size of plain_modulus.
        // Remark: plain_modulus_ has enlarged coefficient size set in constructor
        if (destination.coeff_count() != coeff_count || destination.coeff_bit_count() != coeff_bit_count)
        {
            destination.resize(coeff_count, coeff_bit_count);
        }

        // Handle test-mode case.
        if (mode_ == TEST_MODE)
        {
            set_poly_poly(encrypted.pointer(), coeff_count, coeff_uint64_count, destination.pointer());
            modulo_poly_coeffs(destination.pointer(), coeff_count, mod_, pool_);
            return;
        }

//        // Multiply encrypted by secret_key.
//uint64_t myOne = 1;
//std::cout << "about to create one\n";
//BigPoly one("1");
//BigPoly one(secret_key_);
//one.set_zero();
//std::cout << "myPolyOne " << one.to_string() << std::endl;
//        multiply_poly_poly_polymod_coeffmod(encrypted.pointer(), one.pointer(), polymod_, mod_, destination.pointer(), pool_);
//std::cout << "befor loop\n";
destination.duplicate_from(encrypted);
std::cout << "test eq " << (encrypted == destination);
        // For each coefficient, reposition and divide by coeff_div_plain_modulus.
        uint64_t *dest_coeff = destination.pointer();
        Pointer quotient(allocate_uint(coeff_uint64_count, pool_));
        for (int i = 0; i < coeff_count; ++i)
        {
            // Round to closest level by adding coeff_div_plain_modulus_div_two (mod coeff_modulus).
            add_uint_uint_mod(dest_coeff, coeff_div_plain_modulus_div_two_.pointer(), coeff_modulus_.pointer(), coeff_uint64_count, dest_coeff);
//std::cout << "in loop\n";
            // Reposition if it is in upper-half of coeff_modulus.
            bool is_upper_half = is_greater_than_or_equal_uint_uint(dest_coeff, upper_half_threshold_.pointer(), coeff_uint64_count);
            if (is_upper_half)
            {
                sub_uint_uint(dest_coeff, upper_half_increment_.pointer(), coeff_uint64_count, dest_coeff);
            }
//std::cout << "after if\n";
            // Find closest level.
            divide_uint_uint_inplace(dest_coeff, coeff_div_plain_modulus_.pointer(), coeff_uint64_count, quotient.get(), pool_);
            set_uint_uint(quotient.get(), coeff_uint64_count, dest_coeff);
            dest_coeff += coeff_uint64_count;
        }
//std::cout << "dest: " << destination.to_string() << std::endl;
        // Resize the coefficient to the original plain_modulus size
        destination.resize(coeff_count, orig_plain_modulus_bit_count_);
std::cout << "coeff_count " << coeff_count << " orig_plain_modulus_bit_count_ " << orig_plain_modulus_bit_count_ << endl;
    }


void Decryptor::multSkKey(const BigPoly &encrypted, BigPoly &destination)
    {
        // Extract encryption parameters.
        // Remark: poly_modulus_ has enlarged coefficient size set in constructor
        int coeff_count = poly_modulus_.coeff_count();
        int coeff_bit_count = poly_modulus_.coeff_bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);

        // Verify parameters.
        if (encrypted.coeff_count() != coeff_count || encrypted.coeff_bit_count() != coeff_bit_count)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
#ifdef _DEBUG
        if (encrypted.significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(encrypted, coeff_modulus_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
#endif
        // Make sure destination is of right size to perform all computations. At the end we will
        // resize the coefficients to be the size of plain_modulus.
        // Remark: plain_modulus_ has enlarged coefficient size set in constructor
        if (destination.coeff_count() != coeff_count || destination.coeff_bit_count() != coeff_bit_count)
        {
            destination.resize(coeff_count, coeff_bit_count);
        }

        // Handle test-mode case.
        if (mode_ == TEST_MODE)
        {
            set_poly_poly(encrypted.pointer(), coeff_count, coeff_uint64_count, destination.pointer());
            modulo_poly_coeffs(destination.pointer(), coeff_count, mod_, pool_);
            return;
        }

        // Multiply encrypted by secret_key.
        multiply_poly_poly_polymod_coeffmod(encrypted.pointer(), secret_key_.pointer(), polymod_, mod_, destination.pointer(), pool_);

}

    void Decryptor::decrypt(const BigPoly &encrypted, BigPoly &destination)
    {
        // Extract encryption parameters.
        // Remark: poly_modulus_ has enlarged coefficient size set in constructor
        int coeff_count = poly_modulus_.coeff_count();
        int coeff_bit_count = poly_modulus_.coeff_bit_count();
        int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);

        // Verify parameters.
        if (encrypted.coeff_count() != coeff_count || encrypted.coeff_bit_count() != coeff_bit_count)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
#ifdef _DEBUG
        if (encrypted.significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(encrypted, coeff_modulus_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
#endif
        // Make sure destination is of right size to perform all computations. At the end we will
        // resize the coefficients to be the size of plain_modulus.
        // Remark: plain_modulus_ has enlarged coefficient size set in constructor
        if (destination.coeff_count() != coeff_count || destination.coeff_bit_count() != coeff_bit_count)
        {
            destination.resize(coeff_count, coeff_bit_count);
        }

        // Handle test-mode case.
        if (mode_ == TEST_MODE)
        {
            set_poly_poly(encrypted.pointer(), coeff_count, coeff_uint64_count, destination.pointer());
            modulo_poly_coeffs(destination.pointer(), coeff_count, mod_, pool_);
            return;
        }

        // Multiply encrypted by secret_key.
        multiply_poly_poly_polymod_coeffmod(encrypted.pointer(), secret_key_.pointer(), polymod_, mod_, destination.pointer(), pool_);

        // For each coefficient, reposition and divide by coeff_div_plain_modulus.
        uint64_t *dest_coeff = destination.pointer();
        Pointer quotient(allocate_uint(coeff_uint64_count, pool_));
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
            divide_uint_uint_inplace(dest_coeff, coeff_div_plain_modulus_.pointer(), coeff_uint64_count, quotient.get(), pool_);
            set_uint_uint(quotient.get(), coeff_uint64_count, dest_coeff);
            dest_coeff += coeff_uint64_count;
        }

        // Resize the coefficient to the original plain_modulus size
        destination.resize(coeff_count, orig_plain_modulus_bit_count_);
std::cout << "ori_plain_mod_bc" << orig_plain_modulus_bit_count_ << std::endl;
    }

    Decryptor::Decryptor(const EncryptionParameters &parms, const BigPoly &secret_key, uint64_t power) :
        poly_modulus_(parms.poly_modulus()), coeff_modulus_(parms.coeff_modulus()), plain_modulus_(parms.plain_modulus()), secret_key_(secret_key), mode_(parms.mode()), orig_plain_modulus_bit_count_(parms.plain_modulus().significant_bit_count())
    {
//std::cout << "cbc SPU in decryptor _: " << secret_key_.coeff_bit_count() << std::endl;
//std::cout << "cbc SPU in decryptor: " << secret_key.coeff_bit_count() << std::endl;
//std::cout << "cbc SPU in decryptor _ after: " << secret_key_.coeff_bit_count() << std::endl;
//std::cout << "cbc SPU in decryptor after: " << secret_key.coeff_bit_count() << std::endl;
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
        if (power == 0)
        {
            throw invalid_argument("power cannot be zero");
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
//std::cout << "cbc SPU in decryptor2: " << secret_key_.coeff_bit_count() << std::endl;
        if (poly_modulus_.coeff_count() != coeff_count || poly_modulus_.coeff_bit_count() != coeff_bit_count)
        {
            poly_modulus_.resize(coeff_count, coeff_bit_count);
//std::cout << "cbc SPU in decryptor11: " << secret_key_.coeff_bit_count() << std::endl;
        }
        if (coeff_modulus_.bit_count() != coeff_bit_count)
        {
            coeff_modulus_.resize(coeff_bit_count);
//std::cout << "cbc SPU in decryptor12: " << secret_key_.coeff_bit_count() << std::endl;
        }
        if (plain_modulus_.bit_count() != coeff_bit_count)
        {
            plain_modulus_.resize(coeff_bit_count);
//std::cout << "cbc SPU in decryptor13: " << secret_key_.coeff_bit_count() << std::endl;
        }
        if (secret_key_.coeff_count() != coeff_count || secret_key_.coeff_bit_count() != coeff_bit_count ||
            secret_key_.significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(secret_key_, coeff_modulus_))
        {
//std::cout << "cbc SPU in decryptor10: " << secret_key_.coeff_bit_count() << std::endl;
if(secret_key_.coeff_count() != coeff_count)
            throw invalid_argument("secret_key is not valid for encryption parameters 1");
if(secret_key_.coeff_bit_count() != coeff_bit_count){
//std::cout << "coeff_bit_count " << coeff_bit_count << std::endl;
//std::cout << "sk.coeff_bit_count " << secret_key_.coeff_bit_count() << std::endl;
            throw invalid_argument("secret_key is not valid for encryption parameters 2");
}
if(secret_key_.significant_coeff_count() == coeff_count)
            throw invalid_argument("secret_key is not valid for encryption parameters 3");
if(!are_poly_coefficients_less_than(secret_key_, coeff_modulus_)){
//std::cout << "coeff_modulus_ " << coeff_modulus_.to_string() << std::endl;
            throw invalid_argument("secret_key is not valid for encryption parameters 4");
}
            throw invalid_argument("secret_key is not valid for encryption parameters here");
        }

        // Calculate coeff_modulus / plain_modulus.
        coeff_div_plain_modulus_.resize(coeff_bit_count);
        Pointer temp(allocate_uint(coeff_uint64_count, pool_));
        divide_uint_uint(coeff_modulus_.pointer(), plain_modulus_.pointer(), coeff_uint64_count, coeff_div_plain_modulus_.pointer(), temp.get(), pool_);

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
        if (mode_ == TEST_MODE)
        {
            mod_ = Modulus(plain_modulus_.pointer(), coeff_uint64_count, pool_);
        }
        else
        {
            mod_ = Modulus(coeff_modulus_.pointer(), coeff_uint64_count, pool_);
        }

        // Raise level of secret key.
        if (power > 1)
        {
            exponentiate_poly_polymod_coeffmod(secret_key_.pointer(), &power, 1, polymod_, mod_, secret_key_.pointer(), pool_);
        }
    }
}
