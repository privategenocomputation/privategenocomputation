#include "THE_U.h"
//#include "seal"

using namespace std;

namespace the{
	The::The_U(){
		// FIXME Where do I get the evalKeys?
		EvaluationKeys evaluation_keys = generator.evaluation_keys()
		// XXX Need to store the evaluator
		//Generate evaluator
		Evaluator evaluator(parms, evaluationKeys);
};

	The::add(const BigPoly &cypherText_1, const BigPoly &cypherText_2){
		return evaluator.add(cypherText_1, cypherText_2);
	};

	The::mult(const BigPoly &cypherText_1, const BigPoly &cypherText_2){
		return evaluator.multiply(cypherText_1, cypherText_2);
	};

	The::shareDec_U(const BigPoly &secretKey_U, const BigPoly &cypherText){
		return The::add(The::mult(secretKey_U, cypherText), e_U)
	};

// XXX Work to do... Separate class for MU? hierarchy
	The::combine(const BigPoly &cypherText_SPU, const BigPoly &cypherText_MU){
	//	return The::add(cypherText_SPU, cypherText_MU);
		BigPoly destination;
		// XXX decryptor no key
		BigPoly sumPatialDecrypt = The::add(cypherText_SPU, cypherText_MU);
		// TODO t/q and round and mod t
        // For each coefficient, reposition and divide by coeff_div_plain_modulus.
        uint64_t *dest_coeff = destination.pointer();
        Pointer quotient(allocate_uint(coeff_uint64_count, sumPartialDecrypt));
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
            divide_uint_uint_inplace(dest_coeff, coeff_div_plain_modulus_.pointer(), coeff_uint64_count, quotient.get(), sumPartialDecrypt);
            set_uint_uint(quotient.get(), coeff_uint64_count, dest_coeff);
            dest_coeff += coeff_uint64_count;
        }
		return destination
	};
};
