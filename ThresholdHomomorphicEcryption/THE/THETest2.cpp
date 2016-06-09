// Test2
#include <iostream>
#include "seal.h"
#include "bigpolyarith.h"

using namespace std;
using namespace seal;

// Printing
void printResult(int r1, int r2){
	if(r1 == r2)
		cout << "[OK]\t";
	else
		cout << "[  ]\t";
	cout << r1 << " (expected: " << r2 << ")" << endl;
};

/*
// Decryption
int testDec(BigPoly r,The_U mySPU,The_U myMU){
cout << "testDec: c_MU" << endl;
	BigPoly c_MU = myMU.shareDec_U(r);
cout << "testDec: c_SPU" << endl;
	BigPoly c_SPU = mySPU.shareDec_U(r);
	return (int) myMU.combine(c_MU, c_SPU);
};
*/
void pState(string s){
	cout << s << "..." << endl;
}
int main(){
	// XXX Define parameters
	pState("Init params");
	EncryptionParameters parms;
	parms.poly_modulus() = "1x^2048 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1 << 8;
	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	// Creating KeyGen
	pState("KeyGen");
	KeyGenerator generator_H(parms);
		generator_H.generate();
		BigPoly publicKey_H = generator_H.public_key();
		BigPoly secretKey_H = generator_H.secret_key();
//cout << "cbc H" << secretKey_H.coeff_bit_count() << endl;
		//Generate evaluation keys
		EvaluationKeys evaluationKey(generator_H.evaluation_keys());
		Evaluator evaluator(parms, evaluationKey);
		//Generate MU key
		KeyGenerator generator_MU(parms);
		generator_MU.generate();
		BigPoly secretKey_MU = generator_MU.secret_key();
//cout << "cbc MU" << secretKey_MU.coeff_bit_count() << endl;
		//Generate SPU key
KeyGenerator testGen(parms);
testGen.generate();
//std::cout << "is equal? " << (testGen.secret_key() == secretKey_H) << std::endl;
		BigPolyArith bpa;
		BigPoly secretKey_SPU = bpa.sub(generator_H.secret_key(), secretKey_MU, parms.coeff_modulus());
//cout << "cbc SPU" << secretKey_SPU.coeff_bit_count() << endl;
cout << "decr MU";
Decryptor decryptorMU(parms, secretKey_MU);
cout << "\t[OK]" << endl;
cout << "decr SPU";
Decryptor decryptorSPU(parms, secretKey_SPU);
cout << "\t[OK]" << endl;
		//Set Encoder
//		BalancedEncoder encoder(parms.plain_modulus());
		BinaryEncoder encoder(parms.plain_modulus());
cout << "plain_modulus_cbc: " << encoder.plain_modulus().significant_bit_count() << endl;
		//Set Encryptor
//std::cout << "prout!" << std::endl;
		Encryptor encryptor(parms, generator_H.public_key());
//std::cout << "bitch, plz!" << std::endl;
		//Retrive normal noise
		// XXX Is the E recovered correctly?
		//return set_poly_coeffs_normal(noise.get());
		BigPoly e_SPU = encryptor.getE();
		BigPoly e_MU = encryptor.getE();

// Seal test
	pState("Seal test");
	const int test = 123456789;
	BigPoly encr = encryptor.encrypt(encoder.encode(test));
cout << "cbc encr: " << encr.coeff_bit_count() << endl;
	Decryptor decryptorH(parms, secretKey_H);
//	cout << test << " : " <<encoder.decode_uint64(decryptorH.decrypt(encr)) << endl;
	printResult(test,encoder.decode_uint64(decryptorH.decrypt(encr)));

	// Test integers
	pState("Creating test ints");
	
	const int t1 = 67;
	const int t2 = 2;
	const int t3 = 3;
	const int t4 = 4;

	// Ecryption
	pState("Encryption");
	BigPoly c1 = encryptor.encrypt(encoder.encode(t1));
	BigPoly c2 = encryptor.encrypt(encoder.encode(t2));
	BigPoly c3 = encryptor.encrypt(encoder.encode(t3));
	BigPoly c4 = encryptor.encrypt(encoder.encode(t4));

	// Decryption test
	pState("Decryption test");
//	printResult(testDec(c1, mySPU, myMU), t1);
cout << "cbc c1: " << c1.coeff_bit_count() << endl;
cout << "c1_SPU";
BigPoly c1_SPU = evaluator.add(decryptorSPU.multSkKey(c1), encryptor.getE());
cout << "\t[OK]" << endl;
cout << "cbc c1_SPU: " << c1_SPU.coeff_bit_count() << endl;
cout << "c1_MU";
BigPoly c1_MU = evaluator.add(decryptorMU.multSkKey(c1), encryptor.getE());
cout << "\t[OK]" << endl;
cout << "cbc c1_MU: " << c1_MU.coeff_bit_count() << endl;
cout << "c1_c";
//BigPoly summ = evaluator.add(c1_SPU, c1_MU);
//cout << summ.to_string() << endl;
BigPoly c1_c = decryptorMU.lastStep(evaluator.add(c1_SPU, c1_MU));
cout << "\t[OK]" << endl;
cout << "cbc c1_c: " << c1_c.coeff_bit_count() << endl;
//cout << "c1_c " << c1_c.to_string() << endl;

cout << "decode";
uint64_t result = encoder.decode_uint64(c1_c);
cout << "\t[OK]" << endl;

cout << "res: " << result << endl;;
/*
	// Arythmetic
	pState("Performing Arytmetics");
	// Addition
	pState("\tAdditions");
	BigPoly a1 = mySPU.add(c1,c2);
	BigPoly a2 = mySPU.add(a1,c3);
	BigPoly a3 = mySPU.add(a2,c4);
	// Multiplication
	pState("\tMultiplications");
	BigPoly m1 = mySPU.mult(c1,c2);
	BigPoly m2 = mySPU.mult(m1,c3);
	BigPoly m3 = mySPU.mult(m2,c4);

	// Printing results
	pState("Results");
	cout << "--Add--" << endl;
	printResult(testDec(a1, mySPU, myMU), t1+t2);
	printResult(testDec(a2, mySPU, myMU), t1+t2+t3);
	printResult(testDec(a3, mySPU, myMU), t1+t2+t3+t4);
	cout << "--Mul--" << endl;
	printResult(testDec(m1, mySPU, myMU), t1*t2);
	printResult(testDec(m2, mySPU, myMU), t1*t2*t3);
	printResult(testDec(m3, mySPU, myMU), t1*t2*t3*t4);

	return 1;
*/
}
