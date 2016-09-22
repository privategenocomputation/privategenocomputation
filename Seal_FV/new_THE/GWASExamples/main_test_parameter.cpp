#include <iostream>
#include <vector>
#include <sstream>
#include <cmath>
#include <msgpack.hpp>
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

void example_parameter_selection();

int main() {
    /*// Example: Basics
    example_basics();
    
    // Example: Weighted Average
     example_weighted_average();*/
     // Example: Automatic Parameter Selection
     example_parameter_selection();
     /*// Example: Batching using CRT
     example_batching();
     // Example: Relinearization
     example_relinearization();*/
    
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


void example_parameter_selection()
{
    print_example_banner("Example: Automatic Parameter Selection");
    
    /*
     Here we demonstrate the automatic parameter selection tool. Suppose we want to find parameters
     that are optimized in a way that allows us to evaluate the polynomial 42x^3-27x+1. We need to know
     the size of the input data, so let's assume that x is an integer with base-3 representation of length
     at most 10.
     */
    cout << "Finding optimized parameters for computing 232x*y*z-42x^3-27y+1 ... "<<endl;
    
    ChooserEncoder chooser_encoder;
    ChooserEncryptor chooser_encrypt;
    ChooserEvaluator chooser_evaluator;
    
    /*
     First create a ChooserPoly representing the input data. You can think of this modeling a freshly
     encrypted cipheretext of a plaintext polynomial with length at most 10 coefficients, where the
     coefficients have absolute value at most 1.
     */
    ChooserPoly cxinput(50, 2);
    ChooserPoly cyinput(30, 2);
    ChooserPoly czinput(50, 2);
    
    vector<ChooserPoly> cmul1= {cxinput, cyinput, czinput};
    ChooserPoly cterm0=chooser_evaluator.multiply_many(cmul1);
    cterm0 = chooser_evaluator.relinearize(cterm0, 2);
    cterm0 = chooser_evaluator.multiply_plain(cterm0, chooser_encoder.encode(232));
    cout<< "before computing first term"<<endl;
    // Compute the first term
    ChooserPoly ccubed_input = chooser_evaluator.exponentiate(cxinput, 3);
    ChooserPoly cterm1 = chooser_evaluator.multiply_plain(ccubed_input, chooser_encoder.encode(42));
    
    // Compute the second term
    ChooserPoly cterm2 = chooser_evaluator.multiply_plain(cyinput, chooser_encoder.encode(27));
    
    // Subtract the first two terms
    ChooserPoly csum12 = chooser_evaluator.add(cterm1, cterm2);
    csum12 = chooser_evaluator.sub(cterm0, csum12);
    
    // Add the constant term 1
    ChooserPoly cresult = chooser_evaluator.add_plain(csum12, chooser_encoder.encode(1));
    
    // To find an optimized set of parameters, we use ChooserEvaluator::select_parameters(...).
    EncryptionParameters optimal_parms;
    cout<< "before selecting parameter"<<endl;
    chooser_evaluator.select_parameters(cresult, optimal_parms);
    
    cout << "done." << endl;
    
    // Let's print these to see what was recommended
    cout << "Selected parameters:" << endl;
    cout << "{ poly_modulus: " << optimal_parms.poly_modulus().to_string() << endl;
    cout << "{ coeff_modulus: " << optimal_parms.coeff_modulus().to_string() << endl;
    cout << "{ plain_modulus: " << optimal_parms.plain_modulus().to_dec_string() << endl;
    cout << "{ decomposition_bit_count: " << optimal_parms.decomposition_bit_count() << endl;
    cout << "{ noise_standard_deviation: " << optimal_parms.noise_standard_deviation() << endl;
    cout << "{ noise_max_deviation: " << optimal_parms.noise_max_deviation() << endl;
    
    // Let's try to actually perform the homomorphic computation using the recommended parameters.
    // Generate keys.
    cout << "Generating keys..." << endl;
    KeyGenerator generator(optimal_parms);
    generator.generate();
    cout << "... key generation complete" << endl;
    BigPolyArray public_key = generator.public_key();
    BigPoly secret_key = generator.secret_key();
    
    // Create the encoding/encryption tools
    BalancedEncoder encoder(optimal_parms.plain_modulus());
    Encryptor encryptor(optimal_parms, public_key);
    Evaluator evaluator(optimal_parms);
    Decryptor decryptor(optimal_parms, secret_key);
    
    // Now perform the computations on real encrypted data.
    int x_input = 12345;
    int y_input = 23;
    int z_input = 23456;
    BigPoly x_plain_input = encoder.encode(x_input);
    BigPoly y_plain_input = encoder.encode(y_input);
    BigPoly z_plain_input = encoder.encode(z_input);
    
    
    cout << "Encrypting ... ";
    BigPolyArray cx_input = encryptor.encrypt(x_plain_input);
    BigPolyArray cy_input = encryptor.encrypt(y_plain_input);
    BigPolyArray cz_input = encryptor.encrypt(z_plain_input);
    vector<BigPolyArray> enc_vec = {cx_input, cy_input, cz_input};
    BigPolyArray enc_mul = evaluator.multiply_many(enc_vec);
    
    int evaluation_key_size=enc_mul.size()-2;
    generator.generate_evaluation_keys(evaluation_key_size);
    EvaluationKeys evaluation_keys = generator.evaluation_keys();
    Evaluator evaluator2(optimal_parms, evaluation_keys);
    BigPolyArray enc_term0;
    evaluator2.relinearize(enc_mul, enc_term0, 2);
    BigPolyArray term0 = evaluator.multiply_plain(enc_term0, encoder.encode(232));
    cout << "done." << endl;
    
    // Compute the first term
    cout << "Computing first term ... ";
    BigPolyArray cubed_input = evaluator.exponentiate(cx_input, 3);
    BigPolyArray term1 = evaluator.multiply_plain(cubed_input, encoder.encode(42));
    cout << "done." << endl;
    
    // Compute the second term
    cout << "Computing second term ... ";
    BigPolyArray term2 = evaluator.multiply_plain(cy_input, encoder.encode(27));
    cout << "done." << endl;
    
    // Subtract the first two terms
    cout << "Subtracting first two terms ... ";
    BigPolyArray sum12 = evaluator.add(term1, term2);
    sum12 = evaluator.sub(term0, sum12);
    cout << "done." << endl;
    
    // Add the constant term 1
    cout << "Adding one ... ";
    BigPolyArray result = evaluator.add_plain(sum12, encoder.encode(1));
    cout << "done." << endl;
    
    // Decrypt and decode
    cout << "Decrypting ... ";
    BigPoly plain_result = decryptor.decrypt(result);
    cout << "done." << endl;
    
    // Finally print the result
    cout << "Polynomial 232x*y*z-42x^3-27y+1 evaluated at x=12345, y=23, z=23456: " << encoder.decode_int64(plain_result) << endl;
    if (encoder.decode_int64(plain_result)==(232*x_input*y_input*z_input-42*x_input^3-27*y_input+1)) {
        cout << "evaluation correct"<<endl;
    }
    
    // How much noise did we end up with?
    cout << "Noise in the result: " << inherent_noise(result, optimal_parms, secret_key).significant_bit_count()
    << "/" << inherent_noise_max(optimal_parms).significant_bit_count() << " bits" << endl;
}


