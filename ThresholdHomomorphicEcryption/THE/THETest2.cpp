// Test2
#include <iostream>
#include "seal.h"
#include "bigpolyarith.h"

#include <string>

using namespace std;
using namespace seal;

const string  ESC("\033");
const string PR(ESC + "[31;3m");
const string PY(ESC + "[33;2m");
const string PG(ESC + "[32;1m");
const string PN(ESC + "[0m");
const string PS(ESC + "[35;2m");

const string greenOk(PG+"OK"+PN);
const string yellowOk(PY+"OK"+PN);
const string redErr(PR+"##"+PN);
const string redEx(PR+"XX"+PN);

// Printing
void printResult(int r1, int r2){
	if(r1 == r2){
		cout << "[" << greenOk << "]\t";
	}
	else{
		cout << "[" << redErr << "]\t";
	}
	cout << r1 << " (expected: " << r2 << ")" << endl;
};


// Decryption
int testDec(BigPoly r, Evaluator &evaluator, Decryptor &decryptorSPU, Decryptor &decryptorMU, BigPoly e, BinaryEncoder &encoder, int v = 1){
//cout << "testDecryp: c_MU";
	BigPoly c_MU = evaluator.add(decryptorSPU.multSkKey(r), e);
//cout << "\t[" << yellowOk << "]" << endl;
//cout << "testDecryp: c_SPU";
	BigPoly c_SPU = evaluator.add(decryptorMU.multSkKey(r), e);
//cout << "\t[" << yellowOk << "]" << endl;
//cout << "testCombin:";
BigPoly lol = decryptorMU.lastStep(evaluator.add(c_SPU, c_MU));
//cout << "\t[" << yellowOk << "]" << endl;
if(v) cout << "testDecode:";
uint64_t result = 0;
try{
result = encoder.decode_uint64(lol);
}catch ( const exception &e){
if(!v)cout << "testDecode:";
cout << "\t[" << redEx << "] -- " << e.what() << endl;
return (int) result;
}
if(v) cout << "\t[" << yellowOk << "]" << endl;
	return (int) result;
};

void pState(string s){
	cout << PS << s << "..."  << PN << endl;
}
int main(){
	// XXX Define parameters
	pState("Init params");
	EncryptionParameters parms;
	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(4096);
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
cout << "\t["+ yellowOk +"]" << endl;
cout << "decr SPU";
Decryptor decryptorSPU(parms, secretKey_SPU);
cout << "\t["+ yellowOk +"]" << endl;
		//Set Encoder
//		BalancedEncoder encoder(parms.plain_modulus());
		BinaryEncoder encoder(parms.plain_modulus());
//cout << "plain_modulus_cbc: " << encoder.plain_modulus().significant_bit_count() << endl;
		//Set Encryptor
//std::cout << "prout!" << std::endl;
		Encryptor encryptor(parms, generator_H.public_key());
//std::cout << "bitch, plz!" << std::endl;
		//Retrive normal noise
		// XXX Is the E recovered correctly?
		//return set_poly_coeffs_normal(noise.get());
		BigPoly e_SPU = encryptor.getE();
		BigPoly e_MU = encryptor.getE();
		BigPoly e = encryptor.getE();

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
//cout << "cbc c1: " << c1.coeff_bit_count() << endl;
//cout << "c1_SPU";
BigPoly c1_SPU = evaluator.add(decryptorSPU.multSkKey(c1), e);
//cout << "\t[OK]" << endl;
//cout << "cbc c1_SPU: " << c1_SPU.coeff_bit_count() << endl;
//cout << "c1_MU";
BigPoly c1_MU = evaluator.add(decryptorMU.multSkKey(c1), e);
//cout << "\t[OK]" << endl;
//cout << "cbc c1_MU: " << c1_MU.coeff_bit_count() << endl;
//cout << "c1_c";
//BigPoly summ = evaluator.add(c1_SPU, c1_MU);
//cout << summ.to_string() << endl;
BigPoly c1_c = decryptorMU.lastStep(evaluator.add(c1_SPU, c1_MU));
//cout << "\t[OK]" << endl;
//cout << "cbc c1_c: " << c1_c.coeff_bit_count() << endl;
//cout << "c1_c " << c1_c.to_string() << endl;

//cout << "decode";
uint64_t result = encoder.decode_uint64(c1_c);
//cout << "\t[OK]" << endl;
//cout << "res: " << result << endl;
printResult(result, t1);

	// Arythmetic
	pState("Performing Arytmetics");
	// Addition
	pState("\tAdditions");
	BigPoly a1 = evaluator.add(c1,c2);
	BigPoly a2 = evaluator.add(a1,c3);
	BigPoly a3 = evaluator.add(a2,c4);
	// Multiplication
	pState("\tMultiplications");
	BigPoly m1 = evaluator.multiply(c1,c2);
	BigPoly m2 = evaluator.multiply(m1,c3);
	BigPoly m3 = evaluator.multiply(m2,c4);

	// Printing results
	pState("Results");
	cout << "--Add--" << endl;
	printResult(testDec(a1, evaluator, decryptorMU, decryptorSPU, e, encoder), t1+t2);
	printResult(testDec(a2, evaluator, decryptorMU, decryptorSPU, e, encoder), t1+t2+t3);
	printResult(testDec(a3, evaluator, decryptorMU, decryptorSPU, e, encoder), t1+t2+t3+t4);
	cout << "--Mul--" << endl;
	printResult(testDec(m1, evaluator, decryptorMU, decryptorSPU, e, encoder), t1*t2);
	printResult(testDec(m2, evaluator, decryptorMU, decryptorSPU, e, encoder), t1*t2*t3);
	printResult(testDec(m3, evaluator, decryptorMU, decryptorSPU, e, encoder), t1*t2*t3*t4);

// looping for max value
pState("looking for max value");
int res = 0;
int i = 0;
	BigPoly one = encryptor.encrypt(encoder.encode(1));
	printResult(testDec(one, evaluator, decryptorMU, decryptorSPU, e, encoder, 0), 1);
	BigPoly acc = evaluator.add(one,one);
	printResult(testDec(acc, evaluator, decryptorMU, decryptorSPU, e, encoder, 0), 2);
for (i = 3; i < 10; i++){
	acc = evaluator.add(acc,one);
	res = testDec(acc, evaluator, decryptorMU, decryptorSPU, e, encoder, 0);
//	printResult(res, i);
	if (res == 0){
		printResult(res, i);
		break;
	}
}
cout << "looped " << i << " times\n"; 
printResult(res, --i);

// looping for chaine mult
pState("looking for max chained mult");
	acc = evaluator.add(one,one);
	//BigPoly temp = encryptor.encrypt(encoder.encode(1));

for (i = 1; i < 10; i++){
	//temp = encryptor.encrypt(encoder.encode(i));
	acc = evaluator.multiply(one,acc);
	res = testDec(acc, evaluator, decryptorMU, decryptorSPU, e, encoder, 0);
//	printResult(res, i);
	if (res == 0){
		printResult(res, 2);
		break;
	}
}
cout << "looped " << i << " times\n"; 
printResult(res, 2);
// 16384 --> 21

// line comb
pState("testing linear combinason minimal");
//	one = encryptor.encrypt(encoder.encode(1));
	BigPoly mul1 = evaluator.multiply(one,one);
	mul1 = evaluator.multiply(mul1,one);
	acc = evaluator.add(mul1,mul1);
printResult(testDec(evaluator.add(mul1, evaluator.multiply(evaluator.multiply(one,one), one)), evaluator, decryptorMU, decryptorSPU, e, encoder), 2);
for (i = 1; i < 500; i++){
	acc = evaluator.add(acc,mul1);
	res = testDec(acc, evaluator, decryptorMU, decryptorSPU, e, encoder, 0);
//	printResult(res, i);
	if (res == 0){
		printResult(res, i+2);
		break;
	}
}
cout << "looped " << i << " times\n"; 
printResult(res, i+1);




	return 0;

}
