#include <iostream>
#include <vector>
#include <sstream>
#include "decryptorT.h"
#include "hkeyGen.h"
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
#include "util/uintarithmod.h"
#include "util/polyextras.h"
//#include "decryptor.h"
using namespace std;
using namespace seal;
using namespace seal::util;

void print_example_banner(string title);

void example_basics();

void set_poly_coeffs_normal(std::uint64_t *poly, UniformRandomGenerator *random,EncryptionParameters *parms);

void compute_secret_key_H_array(int max_power, EncryptionParameters parms, BigPoly& secret_key_H, BigPolyArray& secret_key_H_array);

bool are_poly_coefficients_less_than(const BigPoly &poly, const BigUInt &max_coeff);

void decryptMU(const BigPolyArray &encrypted, BigPoly &destination, BigPoly &cpSPU, BigPolyArray& secret_key_MU_array, EncryptionParameters parms);

void set_poly_coeffs_normal(std::uint64_t *poly, UniformRandomGenerator *random);

int orig_plain_modulus_bit_count_;

BigUInt upper_half_threshold_;

BigUInt upper_half_increment_;

BigUInt coeff_div_plain_modulus_;

BigUInt coeff_div_plain_modulus_div_two_;

util::PolyModulus polymod_;

util::Modulus mod_;

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
BigPoly secret_key_H;

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
    
    // Generate public keys.
    cout << "Generating public keys..." << endl;
    KeyGenerator generator(parms);
    generator.generate();
    cout << "public key generation complete" << endl;
    BigPolyArray public_key_H = generator.public_key();
    
    // Encode two integers as polynomials.
	const int value1 = 3;
	const int value2 = 8;
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encoded1 = encoder.encode(value1);
	BigPoly encoded2 = encoder.encode(value2);
	cout << "Encoded " << value1 << " as polynomial " << encoded1.to_string()
			<< endl;
	cout << "Encoded " << value2 << " as polynomial " << encoded2.to_string()
			<< endl;
    
    
    // Encrypt values.
    cout << "Encrypting values..." << endl;
    Encryptor encryptor(parms, public_key_H);
    BigPolyArray encrypted1 = encryptor.encrypt(encoded1);
    BigPolyArray encrypted2 = encryptor.encrypt(encoded2);
    
    // Perform arithmetic on encrypted values.
    
    cout << "Performing encrypted arithmetic..." << endl;
    Evaluator evaluator(parms);
    /*
     cout << "... Performing negation..." << endl;
     BigPolyArray encryptednegated1 = evaluator.negate(encrypted1);
     cout << "... Performing addition..." << endl;
     BigPolyArray encryptedsum = evaluator.add(encrypted1, encrypted2);*/
    cout << "... Performing subtraction..." << endl;
    BigPolyArray encrypteddiff = evaluator.sub(encrypted1, encrypted2);
    cout << "... Performing multiplication..." << endl;
    BigPolyArray encryptedproduct = evaluator.multiply(encrypted1, encrypted2);
    
    cout << "Test ..." << encrypted1.size() << endl;
    
    // Generate secret keys.
    cout << "Generating secret keys..." << endl;
	BigPoly secret_key_H = generator.secret_key();
    HkeyGen key_h_Gen(parms, secret_key_H);
    int cp_size_minus_1=1;
    key_h_Gen.compute_secret_key_array(cp_size_minus_1);
    BigPolyArray secret_key_H_array;
    secret_key_H_array=key_h_Gen.secret_key_array_;
    cout << "keyarray for h generation complete" << endl;
    /*
    for (int i=0; i<secret_key_H_array.size(); i++) {
        cout<<"secret_key_H_array[i] is: "<<secret_key_H_array[i].to_string()<<endl;
    }*/
    /*
    BigPolyArith bpa;
    BigUInt coeff_modulus = parms.coeff_modulus();
    
    
    int coeff_count = parms.poly_modulus().coeff_count();
    int coeff_bit_count = parms.poly_modulus().coeff_bit_count();
    int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
    BigPolyArray secret_key_MU_array;
    secret_key_MU_array.resize(cp_size_minus_1, coeff_count, coeff_bit_count);
    BigPolyArray secret_key_SPU_array;
    secret_key_SPU_array.resize(cp_size_minus_1, coeff_count, coeff_bit_count);
	KeyGenerator generatorMU(parms);
    
    for (int i=0; i<cp_size_minus_1; i++) {
        generatorMU.generate();
        BigPoly tmp= generatorMU.secret_key();
        set_poly_poly(tmp.pointer(), coeff_count, coeff_uint64_count, secret_key_MU_array.pointer(i));
        BigPoly tmp1;
        bpa.sub(secret_key_H_array[i], tmp, coeff_modulus, tmp1);
        set_poly_poly(tmp1.pointer(), coeff_count, coeff_uint64_count, secret_key_SPU_array.pointer(i));
    }
    
    cout << "... secret keys generation complete" << endl;
    
   
    
    */

    
    BigPolyArray originalCPSPU=encrypteddiff;
    BigPolyArray originalCPMU=encrypteddiff;
    
    cout << "Test ..." << 3 << endl;
    /////////
    //Desabled for testing decryption mode without threshold mechnism.
    ////////
    
    BigPoly cpSPU;
    BigPoly result1;
    cpSPU.set_zero();
    cout<<"encryptedproduct.size is: "<<encrypteddiff.size()<<endl;
    cout<<"secret_key_H_array size is: "<<secret_key_H_array.size()<<endl;
    
    decryptMU(originalCPMU, result1, cpSPU,secret_key_H_array, parms);
    
    /*
    DecryptorT decSPU(parms);
    
    /////////
    //Testing decryption mode without threshold mechnism.
    ////////
    DecryptorT decMU(parms);
    
    BigPoly cpSPU;
    decSPU.decryptSPU(originalCPSPU, cpSPU,secret_key_SPU_array);
    BigPoly result1;
    /////////
    //Testing decryption mode without threshold mechnism.
    ////////
    
    
    
    decMU.decryptMU(originalCPMU, result1, cpSPU,secret_key_MU_array);
    */

    cout << "Decrypting results..." <<endl;

    // Decode results.
    int decoded1 = encoder.decode_int64(result1);

    // Display results.
    cout << "Result decoded is " << decoded1 << endl;
}

void decryptMU(const BigPolyArray &encrypted, BigPoly &destination, BigPoly &cpSPU, BigPolyArray& secret_key_MU_array, EncryptionParameters parms)
{
    
    int coeff_count = parms.poly_modulus().coeff_count();
    int coeff_bit_count = parms.poly_modulus().coeff_bit_count();
    int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
    
    // Verify parameters.
    if (encrypted.size() < 2 || encrypted.coeff_count() != coeff_count || encrypted.coeff_bit_count() != coeff_bit_count)
    {
        throw invalid_argument("encrypted is not valid for encryption parameters");
    }
#ifdef _DEBUG
    for (int i = 0; i < encrypted.size(); ++i)
    {
        if (encrypted[i].significant_coeff_count() == coeff_count || !are_poly_coefficients_less_than(encrypted[i], parms.coeff_modulus()))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
    }
#endif
    
    cout<<" 1111"<<endl;
    // Make sure destination is of right size to perform all computations. At the end we will
    // resize the coefficients to be the size of plain_modulus.
    // Remark: plain_modulus_ has enlarged coefficient size set in constructor
    if (destination.coeff_count() != coeff_count || destination.coeff_bit_count() != coeff_bit_count)
    {
        destination.resize(coeff_count, coeff_bit_count);
    }
    
    MemoryPool &pool = *MemoryPool::default_pool();
    
    /*
     secret_key_array_.resize(1, coeff_count, coeff_bit_count);
     set_poly_poly(secret_key_.pointer(), coeff_count, coeff_uint64_count, secret_key_array_.pointer(0));
     
     // Make sure we have enough secret keys computed
     compute_secret_key_array(encrypted.size() - 1);*/
    
    /*
     Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
     This is equal to Delta m + v where ||v|| < Delta/2.
     So, add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
     Therefore, we can (integer) divide by Delta and the answer will round down to m.
     */
    // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
    
    cout<<" before dot product done"<<endl;
    dot_product_bigpolyarray_polymod_coeffmod(encrypted.pointer(1), secret_key_MU_array.pointer(0), encrypted.size() - 1, polymod_, mod_, destination.pointer(), pool);
    // add c_0 mod into destination
    cout<<"dot product done"<<endl;
    add_poly_poly_coeffmod(destination.pointer(), encrypted[0].pointer(), coeff_count, parms.coeff_modulus().pointer(), coeff_uint64_count, destination.pointer());
    
    //add the second part of decryption result from SPU.
    
    
    add_poly_poly_coeffmod(destination.pointer(), cpSPU.pointer(), coeff_count, parms.coeff_modulus().pointer(), coeff_uint64_count, destination.pointer());
    
    /*
    MemoryPool &poolforrMU = *MemoryPool::default_pool();
    BigPoly errorMU(coeff_count, coeff_bit_count);
    errorMU.set_zero();
    unique_ptr<UniformRandomGenerator> randomMU(UniformRandomGeneratorFactory::default_factory()->create());
    Pointer tempMU(allocate_poly(coeff_count, coeff_uint64_count, poolforrMU));
    set_poly_coeffs_normal(tempMU.get(), randomMU.get());
    add_poly_poly_coeffmod(tempMU.get(), errorMU.pointer(), coeff_count, parms.coeff_modulus().pointer(), coeff_uint64_count, errorMU.pointer());
    add_poly_poly_coeffmod(destination.pointer(), errorMU.pointer(), coeff_count, parms.coeff_modulus().pointer(), coeff_uint64_count, destination.pointer());*/
    
    
    // For each coefficient, reposition and divide by coeff_div_plain_modulus.
    uint64_t *dest_coeff = destination.pointer();
    Pointer quotient(allocate_uint(coeff_uint64_count, pool));
    Pointer big_alloc(allocate_uint(2 * coeff_uint64_count, pool));
    for (int i = 0; i < coeff_count; ++i)
    {
        // Round to closest level by adding coeff_div_plain_modulus_div_two (mod coeff_modulus).
        add_uint_uint_mod(dest_coeff, coeff_div_plain_modulus_div_two_.pointer(), parms.coeff_modulus().pointer(), coeff_uint64_count, dest_coeff);
        
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
/*
void set_poly_coeffs_normal(std::uint64_t *poly, UniformRandomGenerator *random) const
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
}*/
