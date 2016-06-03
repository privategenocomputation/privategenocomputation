#include "THE_CI.cpp"
#include "THE_U.cpp"

using namespace std, the;

int main(){
	// Creating The_CI
	The_CI myCI = The_CI();
	myCI.generate()

	// Creating The_U for SPU and MU
	The_U myMU = The_U(myCI.getParams(), myCI.getSecretKey_MU(), myCI.getEvaluationKey(), myCI.getE_MU());
	The_U mySPU = The_U(myCI.getParams(), myCI.getSecretKey_SPU(), myCI.getEvaluationKey(), myCI.getE_SPU());

	// Test integers
	int t1 = 1;
	int t2 = 2;
	int t3 = 3;
	int t4 = 4;

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

	// Decryption
	int testDec(BigPoly r){
		BigPoly c_SPU = mySPU.shareDec_U(mySPU.getSecretKey(), r);
		BigPoly c_MU = myMU.shareDec_U(myMU.getSecretKey(), r);
		return myMU.combine(c_MU, c_SPU);
	}

	// Printing resluts
	void printResult(int r1, int r2){
		if(r1 == r2)
			printf("[OK]\t");
		else
			printf("[  ]\t");
		printf("%d (%d)\n",r1, r2);
	}

	printf("--Add--");
	printResult(testDec(a1), t1+t2);
	printResult(testDec(a2), t1+t2+t3);
	printResult(testDec(a3), t1+t2+t3+t4);
	printf("--Mul--");
	printResult(testDec(m1), t1*t2);
	printResult(testDec(m2), t1*t2*t3);
	printResult(testDec(m3), t1*t2*t3*t4);
}
