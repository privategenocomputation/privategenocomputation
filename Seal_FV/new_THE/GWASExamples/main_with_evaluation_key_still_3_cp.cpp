#include <iostream>
#include <vector>

#include <sstream>
#include <assert.h>
#include <cstdint>
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
#include "decryptor.h"
//#include "decryptorT.h"

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
    BigUInt &coeff_modulus = parms.coeff_modulus();
    BigUInt &plain_modulus = parms.plain_modulus();
    BigPoly &poly_modulus = parms.poly_modulus();
    parms.decomposition_bit_count() = 4;
    parms.noise_standard_deviation() = 3.19;
    parms.noise_max_deviation() = 35.06;
    coeff_modulus.resize(48);
    coeff_modulus = "FFFFFFFFC001";
    plain_modulus.resize(7);
    plain_modulus = 1 << 6;
    poly_modulus.resize(65, 1);
    poly_modulus[0] = 1;
    poly_modulus[64] = 1;


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

	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPolyArray public_key_H = generator.public_key();
	BigPoly secret_key_H = generator.secret_key();
    
    cout<<"secret_key_H is: "<<secret_key_H.to_string()<<endl;
    
    

	KeyGenerator generatorMU(parms);
	generatorMU.generate(3);
	cout << "... MU generation complete" << endl;
    BigPoly secret_key_MU = generatorMU.secret_key();
    
    
    BigPoly secret_key_SPU;
    
   
    
    BigPolyArith bpa;
    
    bpa.sub(secret_key_H, secret_key_MU, coeff_modulus, secret_key_SPU);
    

    // Encrypt values.
    cout << "Encrypting values..." << endl;
    Encryptor encryptor(parms, public_key_H);
    Evaluator evaluator(parms);
    cout<<"evaluator initialized successfully"<<endl;
    
    BigPolyArray encrypted1 = encryptor.encrypt(encoded1);
    BigPolyArray encrypted2 = encryptor.encrypt(encoded2);

    // Perform arithmetic on encrypted values.
    
    cout << "Performing encrypted arithmetic..." << endl;
    
    
    cout << "... Performing negation..." << endl;
    BigPolyArray encryptednegated1 = evaluator.negate(encrypted1);
    cout << "... Performing addition..." << endl;
    BigPolyArray encryptedsum = evaluator.add(encrypted1, encrypted2);
    cout << "... Performing subtraction..." << endl;
    BigPolyArray encrypteddiff = evaluator.sub(encrypted1, encrypted2);
    cout << "... Performing multiplication..." << endl;
    vector<BigPolyArray> encryptedproductv = { encrypted1, encrypted2, encryptedsum};
    BigPolyArray encryptedproduct = evaluator.multiply_many(encryptedproductv);
    generator.generate_evaluation_keys(2);
    EvaluationKeys evaluation_keys = generator.evaluation_keys();
    Evaluator evaluator2(parms, evaluation_keys);
    BigPolyArray encryptedproduct_relin=evaluator2.relinearize(encryptedproduct);

    cout << "original ciphertext size is: " << encryptedproduct.size() << endl;
    
    cout<<"current ciphertext size is: "<<encryptedproduct_relin.size()<<endl;
    
    /////////
    //Desabled for testing decryption mode without threshold mechnism.
    ////////
    //DecryptorT decMU(parms, secret_key_MU);
    
    
    Decryptor decSPU(parms,secret_key_H);
    
    /////////
    //Testing decryption mode without threshold mechnism.
    ////////
    /*
    DecryptorT decMU(parms,secret_key_MU);
    
    BigPoly cpSPU;
    decSPU.decryptSPU(originalCPSPU, cpSPU);
    BigPoly result1;
    /////////
    //Testing decryption mode without threshold mechnism.
    ////////
    
    
    
    decMU.decryptMU(originalCPMU, result1, cpSPU);*/
    BigPoly result1;
    decSPU.decrypt(encryptedproduct_relin, result1);
    

    cout << "Decrypting results..." <<endl;

    // Decode results.
    int decoded1 = encoder.decode_int64(result1);

    // Display results.
    cout << "Result decoded is " << decoded1 << endl;
}


