// Test2
#include <iostream>
#include "seal.h"
#include "bigpolyarith.h"
#include <string>
#include <sstream>

//Handler for file manipulation
#include "genReader.h"
#include "perfEval.h"
//7
unsigned int GENSTART(4);
//0..2
unsigned int PHESTART(2);
//0..2
unsigned int ANCSTART(2);
//1..191
unsigned int NB_PART(191);
// 4096
unsigned int POLYMOD(4096);

// verbose mode
unsigned int VERB(0);
// super verbose
unsigned int SVERB(VERB);

using namespace std;
using namespace seal;

const string ESC("\033");
const string PR(ESC + "[31;3m");
const string PI(ESC + "[34;1m");
const string PY(ESC + "[33;2m");
const string PT(ESC + "[33;1m");
const string PG(ESC + "[32;1m");
const string PN(ESC + "[0m");
const string PS(ESC + "[35;2m");

const string greenOk(PG+"OK"+PN);
const string yellowOk(PY+"OK"+PN);
const string yOk("\t["+ yellowOk +"]");
const string redErr(PR+"##"+PN);
const string redEx(PR+"XX"+PN);

void pRec(double s, int last=0){
	if (RECORD_MOD == 1) {
		rec << s << ";";
		if(last) rec << endl;
	}
}

// Printing
void verb(string s, int v=VERB){
	if(v) cout << s << flush;
}
;
void printResult(int r1, int r2){
	cout << "\tresult: " << PI << r1 << PN << " (expected: " << PI << r2 << PN << ")";
	if(r1 == r2){
		cout << "\t[" << greenOk << "]";
	}
	else{
		cout << "\t[" << redErr << "]";
	}
	cout << flush;
};

void pState(string s,int rcnl = 0){
	cout << PS << s << PS << "..."  << PN;
	if(rcnl) cout << endl;
	cout << flush;
};

void pOk(int rcnl = 0){
	cout << yOk;
	if(rcnl) cout << endl;
	cout << flush;
};

void pAET(double time = -1, int v = VERB, int rcnl = 1){
	if(v){
		cout << " [" << PT << time << PN <<"]";
		if(rcnl) cout << endl;
		cout << flush;
	}
};

// Decryption
int testDec(BigPoly r, Evaluator &evaluator, Decryptor &decryptorSPU, Decryptor &decryptorMU, BigPoly e, BinaryEncoder &encoder, int v = SVERB){
	int aea, aet;
	aea = 0;
	if(v) cout << "\n\t\ttestDecryp: c_MU";
	Timer t;
	BigPoly c_MU = evaluator.add(decryptorSPU.multSkKey(r), e);
	aet = t.elapsed();
	aea += aet;
	pRec(aet);
	if(v) pOk();
	pAET(aet,v);
	if(v) cout << "\t\ttestDecryp: c_SPU";
	t.reset();
	BigPoly c_SPU = evaluator.add(decryptorMU.multSkKey(r), e);
	aet = t.elapsed();
	aea += aet;
	pRec(aet);
	if(v) pOk();
	pAET(aet,v);
	if(v) cout << "\t\ttestCombin:";
	t.reset();
	BigPoly enc = decryptorMU.lastStep(evaluator.add(c_SPU, c_MU));
	aet = t.elapsed();
	aea += aet;
	pRec(aet);
	if(v) pOk();
	pAET(aet,v);
	if(v) cout << "\t\ttestDecode:";
	uint64_t result = -1;
	try{
	 t.reset();
		result = encoder.decode_uint64(enc);
		aet = t.elapsed();
		aea += aet;
		pRec(aet);
		pRec(aea);
		pAET(aet,v, 0);
	}catch ( const exception &e){
		if(!v)cout << "\t\ttestDecode:";
		cout << "\t[" << redEx << "] -- " << e.what() << endl;
		pRec(-1);
		return (int) result;
	}
	if(v) pOk();
	pAET(aea,v);
	return (int) result;
};

// Linear combinaison
BigPoly combiLin(vector<BigPoly> encGen, vector<BigPoly> encPhe, vector<BigPoly> encAnc, Evaluator &eval, unsigned int par = 0){
	BigPoly m = eval.multiply(eval.multiply(encGen.at(0), encPhe.at(0)), encAnc.at(0));
	BigPoly r;
	r.duplicate_from(m);
	for(unsigned int i = 1; i < ((par==0)?encGen.size():par); i++){
		m = eval.multiply(eval.multiply(encGen.at(i), encPhe.at(i)), encAnc.at(i));
		r = eval.add(r, m);
	}
	return r;
};

// Extract sub vector from start to start + delta
vector<char> extract(vector<char> v, int start, int delta){
	vector<char>::const_iterator first = v.begin() + start;
	vector<char>::const_iterator last = v.begin() + start + delta;
	return vector<char>(first, last);
};

// Enc vector
vector<BigPoly> enc(vector<char> v, Encryptor &encryptor, BinaryEncoder &encoder){
	vector<BigPoly> encV;
	int tmp;
	for(unsigned int i=0; i<v.size(); i++){
		tmp = (int) v.at(i);
		encV.push_back(encryptor.encrypt(encoder.encode(tmp)));
	}
	return encV;
};

// compute the expected value
int expect(vector<char> g, vector<char> p, vector<char> a, int par = 0, int v = SVERB){
	if(v){
		cout << endl << "Printing {gen, phe, anc}" << endl;
		for(unsigned int j=0;j<g.size();j++) cout << (int) g.at(j);
		cout << endl;
		for(unsigned int j=0;j<p.size();j++) cout << (int) p.at(j);
		cout << endl;
		for(unsigned int j=0;j<a.size();j++) cout << (int) a.at(j);
		cout << endl;
	}
	int acc = 0;
	for(unsigned int i = 0; i<((par==0)?g.size():par); i++)
		acc += ((int) g.at(i)) * ((int) p.at(i)) * ((int) a.at(i));
	return acc;
};

// gen, phe, anc, part, poly, rec_mod, v_mod, sv_mod
int main(int argc, char *argv[]){
	if (argc == 10)
		RPATH = argv[9];
	rec.open(RPATH, ios::app);
	if (argc == 9 || argc == 10) {
	stringstream convertGen(argv[1]);
	stringstream convertPhe(argv[2]);
	stringstream convertAnc(argv[3]);
	stringstream convertPar(argv[4]);
	stringstream convertPol(argv[5]);
	stringstream convertRec(argv[6]);
	stringstream convertV(argv[7]);
	stringstream convertSV(argv[8]);
	if(!(convertGen >> GENSTART)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
	if(!(convertPhe >> PHESTART)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
	if(!(convertAnc >> ANCSTART)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
	if(!(convertPar >> NB_PART)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
	if(!(convertPol >> POLYMOD)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
	if(!(convertRec >> RECORD_MOD)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
	if(!(convertV >> VERB)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
	if(!(convertSV >> SVERB)) {
		throw invalid_argument("cannot convert argument given in main");
		return 1;
	}
}

	Timer t;
	double aet, aea;
	pRec(GENSTART);
	pRec(PHESTART);
	pRec(ANCSTART);
	pRec(NB_PART);
	pRec(POLYMOD);
	// Read files
	aea = 0;
	pState("Loading data", 0);
	verb("\n\tLoading names");
	t.reset();
	vector<string> nam = readNames();
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	verb("\tLoading ids");
	t.reset();
	vector<string> ids = readIds();
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	int nbPart = nam.size();
	verb("\tNumber of patients\t["+PI+to_string(nbPart)+PN+"]\n");
	int nbPartWanted = NB_PART;
	if(nbPartWanted > nbPart){
		throw invalid_argument("You want too many patients, not enough partients found");
		return 1;
	}
	verb("\tNumber of patients considered\t["+PI+to_string(nbPartWanted)+PN+"]\n");
	verb("\tLoading genotypes");
	t.reset();
	vector<char> gen = extract(readGen(), GENSTART * nbPart, nbPartWanted);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	verb("\tLoading phenotypes");
	t.reset();
	vector<char> phe = extract(readPhe(), PHESTART * nbPart, nbPartWanted);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	verb("\tLoading ancestries");
	t.reset();
	vector<char> anc = extract(readAnc(), ANCSTART * nbPart, nbPartWanted);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	pOk();
	pAET(aea,1);
	pRec(aea);

	// Define parameters
	aea = 0;
	pState("Init params", 0);
	verb("\n\tPolymod\t["+PI+to_string(POLYMOD)+PN+"]\n");
	t.reset();
	EncryptionParameters parms;
	parms.poly_modulus() = ("1x^" + to_string(POLYMOD) + " + 1");
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(POLYMOD);
	parms.plain_modulus() = 1 << 8;
	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();
	aet = t.elapsed();
	aea += aet;
	pOk();
	pAET(aea,1);
	pRec(aea);

	// Creating KeyGen
	aea = 0;
	pState("KeyGen", 0);
	verb("\n\tBulding KeyGenerator H");
	t.reset();
	KeyGenerator generator_H(parms);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	verb("\tGenerating secretKey H");
	t.reset();
	generator_H.generate();
	BigPoly secretKey_H = generator_H.secret_key();
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	// Generate evaluation keys
	verb("\tRetriving evaluationKeys H");
	t.reset();
	EvaluationKeys evaluationKey(generator_H.evaluation_keys());
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	// Generate MU key
	verb("\tBulding KeyGenerator MU");
	t.reset();
	KeyGenerator generator_MU(parms);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	verb("\tGenerating secretKey MU");
	t.reset();
	generator_MU.generate();
	BigPoly secretKey_MU = generator_MU.secret_key();
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	// Generate SPU key
	verb("\tComputing secretKey SPU");
	t.reset();
	BigPolyArith bpa;
	BigPoly secretKey_SPU = bpa.sub(generator_H.secret_key(), secretKey_MU, parms.coeff_modulus());
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	pOk();
	pAET(aea,1);
	pRec(aea);

	// Generate decs, enco, encr, eval
	aea = 0;
	pState("Generate encryption objects", 0);
	// Set Decryptor SPU/MU
	verb("\n\tBuilding decryptor MU");
	t.reset();
	Decryptor decryptorMU(parms, secretKey_MU);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	verb("\tBuilding decryptor SPU");
	t.reset();
	Decryptor decryptorSPU(parms, secretKey_SPU);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	// Set Encoder
	verb("\tBuilding encoder");
	t.reset();
	BinaryEncoder encoder(parms.plain_modulus());
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	// Set Encryptor
	verb("\tBuilding encryptor");
	t.reset();
	Encryptor encryptor(parms, generator_H.public_key());
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	// Set Evaluator
	verb("\tBuilding evaluator");
	t.reset();
	Evaluator evaluator(parms, evaluationKey);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	// Retrive normal noise
	verb("\tRetriving noise");
	t.reset();
	BigPoly e = encryptor.getE();
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	pOk();
	pAET(aea,1);
	pRec(aea);

	// Ecryption
	aea = 0;
	pState("Encryption");
	verb("\n\tEncrypting genotypes");
	t.reset();
	vector<BigPoly> encGen = enc(gen, encryptor, encoder);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	pRec(aet);
	verb("\tEncrypting phenotypes");
	t.reset();
	vector<BigPoly> encPhe = enc(phe, encryptor, encoder);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	pRec(aet);
	verb("\tEncrypting ancestries");
	t.reset();
	vector<BigPoly> encAnc = enc(anc, encryptor, encoder);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	pRec(aet);
	pOk();
	pAET(aea,1);
	pRec(aea);

	// Linear combinason
	aea = 0;
	pState("Performing linear combinaon");
	verb("\n\tComputing expected result");
	int expected = expect(gen, phe, anc);
	verb("\t["+PI+to_string(expected)+PN+"]");
	verb(yOk+"\n");
	verb("\tComputing linear combinaison");
	t.reset();
	BigPoly r = combiLin(encGen, encPhe, encAnc, evaluator);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	pOk();
	pAET(aea,1);
	pRec(aea);

	// Decryption
	aea = 0;
	pState("Decryption");
	verb("\n\tDecrypting result");
	t.reset();
	int result = testDec(r, evaluator, decryptorMU, decryptorSPU, e, encoder);
	aet = t.elapsed();
	aea += aet;
	verb(yOk);
	pAET(aet);
	printResult(result, expected);
	pAET(aea,1);
	pRec(aea,1);

	rec << flush;
	rec.close();
	return 0;

}
