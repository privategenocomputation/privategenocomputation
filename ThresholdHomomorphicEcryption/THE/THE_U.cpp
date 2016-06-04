#include "THE_U.h"
#include "seal.h"

#include "encryptionparams.h"
#include "util/mempool.h"
#include "util/modulus.h"
#include "util/polymodulus.h"

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

using namespace std;
using namespace seal::util;

namespace the{
	BigPoly The_U::add(const BigPoly &cypherText_1, const BigPoly &cypherText_2){
		return this->evaluator->add(cypherText_1, cypherText_2);
	};

	BigPoly The_U::mult(const BigPoly &cypherText_1, const BigPoly &cypherText_2){
		return this->evaluator->multiply(cypherText_1, cypherText_2);
	};

	BigPoly The_U::shareDec_U(const BigPoly &secretKey_U, const BigPoly &cypherText){
		return this->add(this->mult(secretKey_U, cypherText), this->e_U);
	};

	BigPoly The_U::shareDec_U(const BigPoly &cypherText){
		return this->shareDec_U(this->secretKey_U, cypherText);
	};

	uint64_t The_U::combine(const BigPoly &cypherText_SPU, const BigPoly &cypherText_MU){
		BigPoly result;
		BigPoly sumPartialDecrypt = this->add(cypherText_SPU, cypherText_MU);
		// TODO t/q and round and mod t
		this->partialCombine(sumPartialDecrypt, result);
		// Decode result
				BalancedEncoder encoder(this->params.plain_modulus());
		return encoder.decode_uint64(result);
	};

void The_U::partialCombine(BigPoly &encrypt, BigPoly &destination){
		// XXX ??? XXX
		const int bits_per_uint64 = sizeof(std::uint64_t) * 8;
		BigPoly polyMod = params.poly_modulus();
		int coeff_count = polyMod.coeff_count();
		int coeff_uint64_count = divide_round_up(polyMod.coeff_bit_count(), bits_per_uint64);

		// XXX should be init?
		util::MemoryPool pool_;
		int orig_plain_modulus_bit_count_;
		util::PolyModulus polymod_;
		BigUInt coeff_div_plain_modulus_;
        BigUInt upper_half_increment_;
        BigUInt upper_half_threshold_;
        BigUInt coeff_div_plain_modulus_div_two_;
        BigUInt coeff_modulus_;
        
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
	};
};
