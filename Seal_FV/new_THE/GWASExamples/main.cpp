#include <iostream>
#include <vector>
#include <sstream>
#include "seal.h"
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
#include "decryptor_k.h"
using namespace std;
using namespace seal;
using namespace seal::util;

void print_example_banner(string title);

void example_basics();

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
    const int paramSize = 2048;
    
    // Create encryption parameters.
    //EncryptionParameters parms;
    
    
    /*
     First choose the polynomial modulus. This must be a power-of-2 cyclotomic polynomial,
     i.e. a polynomial of the form "1x^(power-of-2) + 1". We recommend using polynomials of
     degree at least 1024.
     */
    //parms.poly_modulus() = "1x^2048 + 1";
    
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
    //parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(paramSize);
    
    /*
     Now we set the plaintext modulus. This can be any positive integer, even though here we take it to be a
     power of two. A larger plaintext modulus causes the noise to grow faster in homomorphic multiplication,
     and also lowers the maximum amount of noise in ciphertexts that the system can tolerate (see above).
     On the other hand, a larger plaintext modulus typically allows for better homomorphic integer arithmetic,
     although this depends strongly on which encoder is used to encode integers into plaintext polynomials.
     */
    
    //parms.plain_modulus() = 12289;
    
    // Create encryption parameters.
    EncryptionParameters parms;
    
    parms.poly_modulus() = "1x^2048 + 1";
    parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
    cout<<"parms.coeff_modulus() is: "<<parms.coeff_modulus().to_string()<<endl;
    parms.plain_modulus() = 12289;
    parms.decomposition_bit_count() = 47;
    
    cout << "Encryption parameters specify "
    << parms.poly_modulus().significant_coeff_count()
    << " coefficients with "
    << parms.coeff_modulus().significant_bit_count()
    << " bits per coefficient" << endl;
    
    
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
    
    int coeff_count = parms.poly_modulus().coeff_count();
    int coeff_bit_count = parms.poly_modulus().coeff_bit_count();
    int coeff_uint64_count = divide_round_up(coeff_bit_count, bits_per_uint64);
    coeff_uint64_count=2;
    cout<<"coeff_count is:"<<coeff_count<<endl;
    cout<<"coeff_uint64_count is:"<<coeff_uint64_count<<endl;
    BigPolyArray secret_key_MU_array;
    int cp_size_minus_1=1;
    secret_key_MU_array.resize(cp_size_minus_1, coeff_count, coeff_bit_count);
    for (int i=0; i<cp_size_minus_1; i++) {
        generatorMU.generate();
        BigPoly tmp= generatorMU.secret_key();
        set_poly_poly(tmp.pointer(), coeff_count, coeff_uint64_count, secret_key_MU_array.pointer(i));
    }
    
    //BigUInt coeff_modulus = parms.coeff_modulus();
    
    
    // Encrypt values.
    cout << "Encrypting values..." << endl;
    Encryptor encryptor(parms, public_key_H);
    Evaluator evaluator(parms);
    
    
    
    
    /////////////////////////////
    // Encoding integer for homomorphic operation without CRT
    /////////////////////////////
    /*
     const int value1 = 5;
     const int value2 = 7;
     BalancedEncoder encoder(parms.plain_modulus());
     BigPoly encoded1 = encoder.encode(value1);
     BigPoly encoded2 = encoder.encode(value2);
     cout << "Encoded " << value1 << " as polynomial " << encoded1.to_string()
     << endl;
     cout << "Encoded " << value2 << " as polynomial " << encoded2.to_string()
     << endl;
    
    BigPolyArray encrypted1 = encryptor.encrypt(encoded1);
    BigPolyArray encrypted2 = encryptor.encrypt(encoded2);*/
    
    /////////////////////////////
    // Perform arithmetic on encrypted values. Encryption and homomorphic operation with CRT
    /////////////////////////////
    
    // Create the PolyCRTBuilder
    PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
    size_t slot_count = crtbuilder.get_slot_count();
    cout<<"parms.plain_modulus is: "<<parms.plain_modulus().to_string()<<"parms.poly_modulus is: "<<parms.poly_modulus().to_string()<<endl;
    cout<<"slot_count is: "<<slot_count<<endl;
    // Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
    vector<BigUInt> values1(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
    cout<<"parms.plain_modulus().bit_count() is: "<<parms.plain_modulus().bit_count()<<endl;
    int vector_size=200;
    // Set the first few entries of the values vector to be non-zero
    for (int i=0; i<vector_size; i++) {
        values1[i]=rand()%2+1;
    }
    
    // Now compose these into one polynomial using PolyCRTBuilder
    cout << "Plaintext slot contents (slot, value): ";
    for (size_t i = 0; i < vector_size; ++i)
    {
        cout << "(" << i << ", " << values1[i].to_dec_string() << ")" << ((i != vector_size-1) ? ", " : "\n");
    }
    BigPoly plain_composed_poly1 = crtbuilder.compose(values1);
    
    // Encrypt plain_composed_poly
    cout << "Encrypting ... ";
    BigPolyArray encrypted_composed_poly1 = encryptor.encrypt(plain_composed_poly1);
    cout << "done." << endl;
    
    // Now let's try to multiply the squares with the plaintext coefficients (3, 1, 4, 1, 5, 9, 0, 0, ..., 0).
    // First create the coefficient vector
    vector<BigUInt> values2(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
    for (int i=0; i<vector_size; i++) {
        values2[i]=rand()%2+1;
    }
    
    
    // Now compose these into one polynomial using PolyCRTBuilder
    cout << "Plaintext slot contents (slot, value): ";
    for (size_t i = 0; i < vector_size; ++i)
    {
        cout << "(" << i << ", " << values2[i].to_dec_string() << ")" << ((i != vector_size-1) ? ", " : "\n");
    }
    
    // Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
    BigPoly plain_composed_poly2 = crtbuilder.compose(values2);
    
    // Encrypt plain_composed_poly
    cout << "Encrypting ... ";
    BigPolyArray encrypted_composed_poly2 = encryptor.encrypt(plain_composed_poly2);
    cout << "done." << endl;
    
    
    // Now let's try to multiply the squares with the plaintext coefficients (3, 1, 4, 1, 5, 9, 0, 0, ..., 0).
    // First create the coefficient vector
    vector<BigUInt> values3(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
    for (int i=0; i<vector_size; i++) {
        values3[i]=rand()%3+1;
    }
    
    
    // Now compose these into one polynomial using PolyCRTBuilder
    cout << "Plaintext slot contents (slot, value): ";
    for (size_t i = 0; i < vector_size; ++i)
    {
        cout << "(" << i << ", " << values3[i].to_dec_string() << ")" << ((i != vector_size-1) ? ", " : "\n");
    }
    
    // Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
    BigPoly plain_composed_poly3 = crtbuilder.compose(values3);
    
    // Encrypt plain_composed_poly
    cout << "Encrypting ... ";
    BigPolyArray encrypted_composed_poly3 = encryptor.encrypt(plain_composed_poly3);
    cout << "done." << endl;
    
    // Now use multiply_plain to multiply each encrypted slot with the corresponding coefficient
    cout << "Multiplying squared slots with the coefficients ... "<<endl;
    
    
    // Now let's generate the noise sequence for the masking of the plaintext slots other than the first one.
    // First create the coefficient vector
    vector<BigUInt> plaintext_slot_noise(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
    plaintext_slot_noise[0]=0;
    for (int i=1; i<vector_size; i++) {
        plaintext_slot_noise[i]=rand()%12289;
    }
    // Now compose these into one polynomial using PolyCRTBuilder
    cout << "Plaintext slot contents (slot, value): ";
    for (size_t i = 0; i < vector_size; ++i)
    {
        cout << "(" << i << ", " << values3[i].to_dec_string() << ")" << ((i != vector_size) ? ", " : "\n");
    }
    
    // Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
    BigPoly plaintext_slot_noise_poly = crtbuilder.compose(plaintext_slot_noise);
    
    // Encrypt plain_composed_poly
    cout << "Encrypting ... ";
    BigPolyArray encrypted_plaintext_slot_noise_poly = encryptor.encrypt(plaintext_slot_noise_poly);
    cout << "done." << endl;
    
    
    /////////////////////////////
    // Perform triple multiplications
    /////////////////////////////
    
    vector<BigPolyArray> encryptedproductv = { encrypted_composed_poly1, encrypted_composed_poly2, encrypted_composed_poly3};
    BigPolyArray encrypted_triple_product = evaluator.multiply_many(encryptedproductv);
    
    /////////////////////////////
    // Perform one additiona and one multiplication
    /////////////////////////////
    /*
    BigPolyArray encrypted_pair_product = evaluator.add(encrypted_composed_poly1, encrypted_composed_poly2);
    encrypted_pair_product=evaluator.multiply(encrypted_pair_product, encrypted_composed_poly2);
    cout << "original ciphertext size is: " << encrypted_pair_product.size() << endl;
    cout << " done." << endl;*/
    
    /////////////////////////////
    // generating relinearized ciphertext for cipertext with size larger than 2.
    /////////////////////////////
    
    int evaluation_key_size=encrypted_triple_product.size()-2;
    generator.generate_evaluation_keys(evaluation_key_size);
    cout<<"evaluation key successfully generated"<<endl;
    EvaluationKeys evaluation_keys = generator.evaluation_keys();
    Evaluator evaluator2(parms, evaluation_keys);
    BigPolyArray encryptedproduct_relin=evaluator2.relinearize(encrypted_triple_product);
    cout<<"current ciphertext size is: "<<encryptedproduct_relin.size()<<endl;
    
    
    cout << "original ciphertext size is: " << encrypted_triple_product.size() << endl;
    
    
    
    /////////////////////////////
    // Perform encryption, homomorphic operation without CRT
    /////////////////////////////
    /*
    BigPolyArray encryptedproduct=evaluator.multiply(encrypted1, encrypted2);
    generator.generate_evaluation_keys(1);
    EvaluationKeys evaluation_keys = generator.evaluation_keys();
    Evaluator evaluator2(parms, evaluation_keys);
    BigPolyArray encryptedproduct_relin=evaluator2.relinearize(encryptedproduct);
    
    cout << "original ciphertext size is: " << encryptedproduct.size() << endl;
    cout<<"current ciphertext size is: "<<encryptedproduct_relin.size()<<endl;*/
    
    /////////////////////////////
    // Perform threshold decryption with or without CRT
    /////////////////////////////
    
    Decryptor_k decMU(parms,secret_key_H);
    BigPoly cpSPU;
    cpSPU.set_zero();
    BigPoly result1;
    decMU.decryptMU(encryptedproduct_relin, encrypted_plaintext_slot_noise_poly, result1, cpSPU, secret_key_MU_array, vector_size);
    
    
    cout << "Decrypting results..." <<endl;
    
    /////////////////////////////
    // Decryption result with CRT decoding
    /////////////////////////////
    
    // Print the scaled squared slots
    cout << "Scaled squared slot contents (slot, value): ";
    
    for (size_t i = 0; i < vector_size; ++i)
    {
        cout << "(" << i << ", " << crtbuilder.get_slot(result1, i).to_dec_string() << ")" << ((i != vector_size-1) ? ", " : "\n");
    }
    
    BigUInt real_tripleproduct_sum;
    for (int i=0; i < vector_size; ++i) {
        real_tripleproduct_sum=real_tripleproduct_sum.operator+(values1[i].operator*(values2[i].operator*(values3[i])));
    }
    
    if (crtbuilder.get_slot(result1, 0)==real_tripleproduct_sum) {
        cout<<"homomorphic triple product sum computation correct"<<endl;
    }
    /////////////////////////////
    // Decryption result decoding (without CRT)
    /////////////////////////////
    
    /*
    // Decode results.
    int decoded1 = encoder.decode_int64(result1);
    
    // Display results.
    cout << "Result decoded is " << decoded1 << endl;*/
}
