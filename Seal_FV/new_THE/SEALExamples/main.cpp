#include <iostream>
#include <vector>
#include <sstream>

#include "seal.h"

using namespace std;
using namespace seal;

void print_example_banner(string title);

void example_basics();
void example_weighted_average();
void example_parameter_selection();
void example_batching();
void example_relinearization();

int main()
{
    // Example: Basics
    //example_basics();

    // Example: Weighted Average
    //example_weighted_average();

    // Example: Automatic Parameter Selection
    //example_parameter_selection();

    // Example: Batching using CRT
    example_batching();

    // Example: Relinearization
    //example_relinearization();

    // Wait for ENTER before closing screen.
    cout << "Press ENTER to exit" << endl;
    char ignore;
    cin.get(ignore);

    return 0;
}

void print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}



void example_batching()
{
    print_example_banner("Example: Batching using CRT");

    // Create encryption parameters
    EncryptionParameters parms;

    /*
    For PolyCRTBuilder we need to use a plain modulus congruent to 1 modulo 2*degree(poly_modulus), and
    preferably a prime number. We could for example use the following parameters:

    parms.poly_modulus() = "1x^2048 + 1";
    parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
    parms.plain_modulus() = 12289;

    However, the primes suggested by ChooserEvaluator::default_parameter_options() are highly non-optimal 
    in this case. The reason is that the noise growth in many homomorphic operations depends on the remainder
    coeff_modulus % plain_modulus, which is typically close to plain_modulus unless the parameters are carefully 
    chosen. The primes in ChooserEvaluator::default_parameter_options() are chosen so that this remainder is 1 
    when plain_modulus is a (not too large) power of 2, so in the earlier examples this was not an issue. 
    However, here we are forced to take plain_modulus to be odd, and as a result the default parameters are no
    longer optimal at all in this sense.

    Thus, for improved performance when using PolyCRTBuilder, we recommend the user to use their own
    custom coeff_modulus. It should be a prime of the form 2^A - D, where D is as small as possible.
    The plain_modulus should be simultaneously chosen to be a prime congruent to 1 modulo 2*degree(poly_modulus),
    so that in addition coeff_modulus % plain_modulus is 1. Finally, coeff_modulus should be bounded by the 
    same strict upper bounds that were mentioned in example_basics():
    /------------------------------------\
    | poly_modulus | coeff_modulus bound |
    | -------------|---------------------|
    | 1x^1024 + 1  | 48 bits             |
    | 1x^2048 + 1  | 96 bits             |
    | 1x^4096 + 1  | 192 bits            |
    | 1x^8192 + 1  | 384 bits            |
    | 1x^16384 + 1 | 768 bits            |
    \------------------------------------/

    One issue with using such custom primes, however, is that they are never NTT primes, i.e. not congruent 
    to 1 modulo 2*degree(poly_modulus), and hence might not allow for certain optimizations to be used in 
    polynomial arithmetic. Another issue is that the search-to-decision reduction of RLWE does not apply to 
    non-NTT primes, but this is not known to result in any concrete reduction in the security level.

    In this example we use the prime 2^95 - 613077 as our coefficient modulus. The user should try switching 
    between this and ChooserEvaluator::default_parameter_options().at(2048) to observe the difference in the 
    noise level at the end of the computation. This difference becomes significantly greater when using larger
    values for plain_modulus.
    */
    parms.poly_modulus() = "1x^2048 + 1";
    //parms.coeff_modulus() = "7FFFFFFFFFFFFFFFFFF6A52B";
    parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
    parms.plain_modulus() = 12289;

    cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
        << parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;
    
    
    // Let's do some homomorphic operations now. First we need all the encryption tools.
    // Generate keys.
    cout << "Generating keys..." << endl;
    KeyGenerator generator(parms);
    generator.generate();
    cout << "... key generation complete" << endl;
    BigPolyArray public_key = generator.public_key();
    BigPoly secret_key = generator.secret_key();
    
    
    // Create the encryption tools
    Encryptor encryptor(parms, public_key);
    Evaluator evaluator(parms);
    Decryptor decryptor(parms, secret_key);
    
    // Create the PolyCRTBuilder
    PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
    size_t slot_count = crtbuilder.get_slot_count();

    // Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
    vector<BigUInt> values1(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

    // Set the first few entries of the values vector to be non-zero
    values1[0] = 2;
    values1[1] = 3;
    values1[2] = 5;
    values1[3] = 7;
    values1[4] = 11;
    values1[5] = 13;

    // Now compose these into one polynomial using PolyCRTBuilder
    cout << "Plaintext slot contents (slot, value): ";
    for (size_t i = 0; i < 6; ++i)
    {
        cout << "(" << i << ", " << values1[i].to_dec_string() << ")" << ((i != 5) ? ", " : "\n");
    }
    BigPoly plain_composed_poly1 = crtbuilder.compose(values1);


    // Encrypt plain_composed_poly
    cout << "Encrypting ... ";
    BigPolyArray encrypted_composed_poly1 = encryptor.encrypt(plain_composed_poly1);
    cout << "done." << endl;

    // Now let's try to multiply the squares with the plaintext coefficients (3, 1, 4, 1, 5, 9, 0, 0, ..., 0).
    // First create the coefficient vector
    vector<BigUInt> values2(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
    values2[0] = 3;
    values2[1] = 1;
    values2[2] = 4;
    values2[3] = 1;
    values2[4] = 5;
    values2[5] = 9;

    // Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
    BigPoly plain_composed_poly2 = crtbuilder.compose(values2);
    
    
    // Encrypt plain_composed_poly
    cout << "Encrypting ... ";
    BigPolyArray encrypted_composed_poly2 = encryptor.encrypt(plain_composed_poly2);
    cout << "done." << endl;
    
    // Now use multiply_plain to multiply each encrypted slot with the corresponding coefficient
    cout << "Multiplying squared slots with the coefficients ... ";
    BigPolyArray encrypted_pair_product = evaluator.multiply(encrypted_composed_poly1, encrypted_composed_poly2);
    cout << " done." << endl;
    
    cout << "Decrypting the scaled squared polynomial ... ";
    BigPoly plain_pair_product = decryptor.decrypt(encrypted_pair_product);
    cout << "done." << endl;

    // Print the scaled squared slots
    cout << "Scaled squared slot contents (slot, value): ";
    for (size_t i = 0; i < 6; ++i)
    {
        cout << "(" << i << ", " << crtbuilder.get_slot(plain_pair_product, i).to_dec_string() << ")" << ((i != 5) ? ", " : "\n");
    }

    // How much noise did we end up with?
    cout << "Noise in the result: " << inherent_noise(encrypted_pair_product, parms, secret_key).significant_bit_count()
        << "/" << inherent_noise_max(parms).significant_bit_count() << " bits" << endl;
}
