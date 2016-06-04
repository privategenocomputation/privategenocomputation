#include <iostream>
#include "THE_CI.cpp"
#include "THE_U.cpp"
#include "seal.h"

using namespace std;
using namespace seal;
using namespace the;

	// Printing
	void printResult(int r1, int r2){
		if(r1 == r2)
			cout << "[OK]\t";
		else
			cout << "[  ]\t";
		cout << r1 << " (expected: " << r2 << ")" << endl;
	};

	// Decryption
	int testDec(BigPoly r,The_U mySPU,The_U myMU){
		BigPoly c_SPU = mySPU.shareDec_U(r);
		BigPoly c_MU = myMU.shareDec_U(r);
		return (int) myMU.combine(c_MU, c_SPU);
	};

int main(){
	// XXX Define parameters
	EncryptionParameters parms;
	parms.poly_modulus() = "1x^2048 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1 << 8;
	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	// Creating The_CI
	The_CI myCI;
	myCI.gen(parms);

	// Creating The_U for SPU and MU
	The_U myMU{myCI.getParams(), myCI.getSecretKey_MU(), myCI.getEvaluationKey(), myCI.getE_MU()};
	The_U mySPU{myCI.getParams(), myCI.getSecretKey_SPU(), myCI.getEvaluationKey(), myCI.getE_SPU()};

	// Test integers
	const int t1 = 1;
	const int t2 = 2;
	const int t3 = 3;
	const int t4 = 4;

	// Ecryption
	BigPoly c1 = myCI.enc(t1);
	BigPoly c2 = myCI.enc(t2);
	BigPoly c3 = myCI.enc(t3);
	BigPoly c4 = myCI.enc(t4);

	// Arythmetic
	// Addition
	BigPoly a1 = mySPU.add(c1,c2);
	BigPoly a2 = mySPU.add(a1,c3);
	BigPoly a3 = mySPU.add(a2,c4);
	// Multiplication
	BigPoly m1 = mySPU.add(c1,c2);
	BigPoly m2 = mySPU.add(m1,c3);
	BigPoly m3 = mySPU.add(m2,c4);

// Printing results
	cout << "--Add--" << endl;
	printResult(testDec(a1, mySPU, myMU), t1+t2);
	printResult(testDec(a2, mySPU, myMU), t1+t2+t3);
	printResult(testDec(a3, mySPU, myMU), t1+t2+t3+t4);
	cout << "--Mul--" << endl;
	printResult(testDec(m1, mySPU, myMU), t1*t2);
	printResult(testDec(m2, mySPU, myMU), t1*t2*t3);
	printResult(testDec(m3, mySPU, myMU), t1*t2*t3*t4);

	return 1;
}
