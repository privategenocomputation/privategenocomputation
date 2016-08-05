#include <iostream>
#include <vector>
#include <sstream>

#include "bigpoly.h"
#include "bigpolyarith.h"
#include "encryptionparams.h"
#include "encoder.h"
#include "keygenerator.h"
#include "bigpolyarray.h"
#include "evaluator.h"
#include "chooser.h"
#include "encryptor.h"
#include "util/mempool.h"
#include "util/common.h"
#include <algorithm>
#include <stdexcept>
#include "util/common.h"
#include "util/uintarith.h"
#include "util/polyarith.h"
#include "util/polyarithmod.h"
#include "util/clipnormal.h"
#include "util/randomtostd.h"
#include "util/polyarithmod.h"
#include "util/polycore.h"
#include "decryptorCombine.h"
using namespace std;
using namespace seal;
using namespace seal::util;

void print_example_banner(string title);

void example_basics();

void set_poly_coeffs_normal(std::uint64_t *poly, UniformRandomGenerator *random,EncryptionParameters *parms);

int main() {
	// Example: Basics
	example_basics();

	/*// Example: Weighted Average
	 example_weighted_average();

	 // Example: Automatic Parameter Selection
	 example_parameter_selection();

	 // Example: Batching using CRT
	 example_batching();

	 // Example: Relinearization
	 example_relinearization();*/

	// Wait for ENTER before closing screen.
	cout << "Press ENTER to exit" << endl;
	char ignore;
	cin.get(ignore);

	return 0;
}

void print_example_banner(string title) {
	if (!title.empty()) {
		size_t title_length = title.length();
		size_t banner_length = title_length + 2 + 2 * 10;
		string banner_top(banner_length, '*');
		string banner_middle = string(10, '*') + " " + title + " "
				+ string(10, '*');

		cout << endl << banner_top << endl << banner_middle << endl
				<< banner_top << endl << endl;
	}
}

void example_basics() {
	print_example_banner("GWAS EXAMPLE");
	const int paramSize = 4096;

	// Create encryption parameters.
	EncryptionParameters parms;

	/*
	 First choose the polynomial modulus. This must be a power-of-2 cyclotomic polynomial,
	 i.e. a polynomial of the form "1x^(power-of-2) + 1". We recommend using polynomials of
	 degree at least 1024.
	 */
	parms.poly_modulus() = "1x^4096 + 1";

	/*
	 Next choose the coefficient modulus. The values we recommend to be used are:

	 [ degree(poly_modulus), coeff_modulus ]
	 [ 1024, "FFFFFFF00001" ],
	 [ 2048, "3FFFFFFFFFFFFFFFFFF00001"],
	 [ 4096, "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC0000001"],
	 [ 8192, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE00000001"],
	 [ 16384, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000001"].

	 These can be conveniently accessed using ChooserEvaluator::default_parameter_options(),
	 which returns the above list of options as an std::map, keyed by the degree of the polynomial modulus.

	 The user can also relatively easily choose their custom coefficient modulus. It should be a prime number
	 of the form 2^A - 2^B + 1, where A > B > degree(poly_modulus). Moreover, B should be as small as possible
	 for improved efficiency in modular reduction. For security, we recommend strictly adhering to the following
	 size bounds: (see Lepoint-Naehrig (2014) [https://eprint.iacr.org/2014/062])
	 /------------------------------------------------------------------\
    | poly_modulus | coeff_modulus bound | default coeff_modulus       |
	 | -------------|---------------------|-----------------------------|
	 | 1x^1024 + 1  | 48 bits             | 2^48 - 2^20 + 1 (47 bits)   |
	 | 1x^2048 + 1  | 96 bits             | 2^94 - 2^20 + 1 (93 bits)   |
	 | 1x^4096 + 1  | 192 bits            | 2^190 - 2^30 + 1 (189 bits) |
	 | 1x^8192 + 1  | 384 bits            | 2^383 - 2^33 + 1 (382 bits) |
	 | 1x^16384 + 1 | 768 bits            | 2^767 - 2^56 + 1 (766 bits) |
	 \------------------------------------------------------------------/

	 The size of coeff_modulus affects the upper bound on the "inherent noise" that a ciphertext can contain
	 before becoming corrupted. More precisely, every ciphertext starts with a certain amount of noise in it,
	 which grows in all homomorphic operations - in particular in multiplication. Once a ciphertext contains
	 too much noise, it becomes impossible to decrypt. The upper bound on the noise is roughly given by
	 coeff_modulus/plain_modulus (see below), so increasing coeff_modulus will allow the user to perform more
	 homomorphic operations on the ciphertexts without corrupting them. We would like to stress, however, that
	 the bounds given above for coeff_modulus should absolutely not be exceeded.
	 */
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(
			paramSize);

	/*
	 Now we set the plaintext modulus. This can be any positive integer, even though here we take it to be a
	 power of two. A larger plaintext modulus causes the noise to grow faster in homomorphic multiplication,
	 and also lowers the maximum amount of noise in ciphertexts that the system can tolerate (see above).
	 On the other hand, a larger plaintext modulus typically allows for better homomorphic integer arithmetic,
	 although this depends strongly on which encoder is used to encode integers into plaintext polynomials.
	 */
	parms.plain_modulus() = 1 << 8;

	cout << "Encryption parameters specify "
			<< parms.poly_modulus().significant_coeff_count()
			<< " coefficients with "
			<< parms.coeff_modulus().significant_bit_count()
			<< " bits per coefficient" << endl;


	// Encode two integers as polynomials.
	const int value1 = 5;
	const int value2 = -7;
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encoded1 = encoder.encode(value1);
	BigPoly encoded2 = encoder.encode(value2);
	cout << "Encoded " << value1 << " as polynomial " << encoded1.to_string()
			<< endl;
	cout << "Encoded " << value2 << " as polynomial " << encoded2.to_string()
			<< endl;

	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPolyArray public_key_H = generator.public_key();
	BigPoly secret_key_H = generator.secret_key();

	KeyGenerator generatorMU(parms);
	generatorMU.generate();
	cout << "... MU generation complete" << endl;
	BigPoly secret_key_MU = generatorMU.secret_key();

	BigPolyArith bpa;
	BigPoly secret_key_SPU = bpa.sub(secret_key_H, secret_key_MU);

    // Encrypt values.
    cout << "Encrypting values..." << endl;
    Encryptor encryptor(parms, public_key_H);
    BigPolyArray encrypted1 = encryptor.encrypt(encoded1);
    BigPolyArray encrypted2 = encryptor.encrypt(encoded2);

    // Perform arithmetic on encrypted values.
    cout << "Performing encrypted arithmetic..." << endl;
    Evaluator evaluator(parms);
    cout << "... Performing negation..." << endl;
    BigPolyArray encryptednegated1 = evaluator.negate(encrypted1);
    cout << "... Performing addition..." << endl;
    BigPolyArray encryptedsum = evaluator.add(encrypted1, encrypted2);
    cout << "... Performing subtraction..." << endl;
    BigPolyArray encrypteddiff = evaluator.sub(encrypted1, encrypted2);
    cout << "... Performing multiplication..." << endl;
    BigPolyArray encryptedproduct = evaluator.multiply(encrypted1, encrypted2);

    cout << "Test ..." << encrypted1.size() << endl;
    int coeff_count = parms.poly_modulus().coeff_count();
    int coeff_bit_count = parms.poly_modulus().coeff_bit_count();
    int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
    MemoryPool &pool = *MemoryPool::default_pool();
    //unique_ptr<UniformRandomGenerator> random(parms.random_generator()->create());
    //Pointer error(allocate_poly(coeff_count, coeff_uint64_count, pool));


    if (parms.random_generator() == nullptr) {
    	cout << "YES" << endl;
    }
    BigPoly errorSPU(coeff_count, coeff_bit_count);
    errorSPU.set_zero();
    BigPoly errorMU(coeff_count, coeff_bit_count);
    errorMU.set_zero();
    unique_ptr<UniformRandomGenerator> randomSPU(UniformRandomGeneratorFactory::default_factory()->create());
    Pointer tempSPU(allocate_poly(coeff_count, coeff_uint64_count, pool));
    set_poly_coeffs_normal(tempSPU.get(), randomSPU.get(), &parms);
    add_poly_poly_coeffmod(tempSPU.get(), errorSPU.pointer(), coeff_count, parms.coeff_modulus().pointer(), coeff_uint64_count, errorSPU.pointer());

    unique_ptr<UniformRandomGenerator> randomMU(UniformRandomGeneratorFactory::default_factory()->create());
    Pointer tempMU(allocate_poly(coeff_count, coeff_uint64_count, pool));
    set_poly_coeffs_normal(tempMU.get(), randomMU.get(), &parms);
    add_poly_poly_coeffmod(tempMU.get(), errorMU.pointer(), coeff_count, parms.coeff_modulus().pointer(), coeff_uint64_count, errorMU.pointer());

    //SPU
    BigPoly multResultSPU = bpa.multiply(secret_key_SPU,encryptedsum[1]);
    BigPoly addnoiseSPU = bpa.add(multResultSPU,errorSPU);

    //MU
    BigPoly multResultMU = bpa.multiply(secret_key_MU,encryptedsum[1]);
    BigPoly addnoiseMU = bpa.add(multResultMU,errorMU);

    DecryptorCombine dec(parms);

    BigPolyArray cipherToCombine = encryptedsum;
    encryptedsum[1] = bpa.add(addnoiseSPU,addnoiseMU);

    BigPoly result;
    result.set_zero();
    dec.decrypt(encryptedsum, result);

    cout << "Decrypting results..." << endl;

    // Decode results.
    int decoded1 = encoder.decode_int32(result);

    // Display results.
    cout << "Result decoded is " << decoded1 << endl;
}

void set_poly_coeffs_normal(std::uint64_t *poly, UniformRandomGenerator *random, EncryptionParameters *parms)
{
    int coeff_count = parms->poly_modulus().coeff_count();
    int coeff_bit_count = parms->poly_modulus().coeff_bit_count();
    int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
    if (parms->noise_standard_deviation() == 0 || parms->noise_max_deviation() == 0)
    {
        set_zero_poly(coeff_count, coeff_uint64_count, poly);
        return;
    }
    RandomToStandardAdapter engine(random);
    ClippedNormalDistribution dist(0, parms->noise_standard_deviation(), parms->noise_max_deviation());
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
            sub_uint_uint(parms->coeff_modulus().pointer(), poly, coeff_uint64_count, poly);
        }
        else
        {
            set_zero_uint(coeff_uint64_count, poly);
        }
        poly += coeff_uint64_count;
    }
    set_zero_uint(coeff_uint64_count, poly);
}
