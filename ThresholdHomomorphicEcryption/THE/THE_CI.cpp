#include "THE_CI.h"
//#include "seal"

using namespace std;

namespace the{
	The::The_CI(){
	};

	The::gen(const EncryptionParameters &parms){
		// XXX Is it correct?
		this.params = params;

		//Set parameters for poly arithmetic
		const int bits_per_uint64 = sizeof(std::uint64_t) * 8;
		BigPoly polyMod = params.poly_modulus();
		int coeff_count = polyMod.coeff_count();
		int coeff_uint64_count = divide_round_up(polyMod.coeff_bit_count(), bits_per_uint64);

		//Generate keys
		//Generate H keys
		KeyGenerator generator_H(parms);
		generator_H.generate();
		this.publicKey_H = generator_H.public_key();
		this.secretKey_H = generator_H.secret_key();
		//Generate evaluation keys
		this.evaluationKey = generator_H.evaluation_keys();
		//Generate MU key
		KeyGenerator generator_MU(parms);
		generator_MU.generate();
		this.secretKey_MU = generator_MU.secret_key();
		//Generate SPU key
		sub_poly_poly(this.secretKey_H, this.secretKey_MU, coeff_count, coeff_uint64_count, this.secretKey_SPU);
		// TODO Store encoder
		//Set Encoder
		BalancedEncoder encoder(parms.plain_modulus());
		// TODO Store encryptor
		//Set Encryptor
		Encryptor encryptor(parms, publicKey_H);
		//Retrive normal noise
		// XXX Is the E recovered correctly?
		//return set_poly_coeffs_normal(noise.get());
		this.e_SPU = encryptor.getE();
		this.e_MU = encryptor.getE();
	};

	The::enc(const BigPoly &publicKey, const BigPoly &plainText){
		BigPoly encodedText = encoder.encode(plainText);
		return encryptor.encrypt(plainText);
	};

	The::enc(const BigPoly &plainText){
		return this.enc(this.publicKey, playnText);
	};
};
