#include "THE_CI.h"
#include "seal.h"

using namespace std;

namespace the{
	void The_CI::gen(const EncryptionParameters &params){
		this->params = params;

		//Set parameters for poly arithmetic
		const int bits_per_uint64 = sizeof(std::uint64_t) * 8;
		BigPoly polyMod = params.poly_modulus();
		int coeff_count = polyMod.coeff_count();
		int coeff_uint64_count = divide_round_up(polyMod.coeff_bit_count(), bits_per_uint64);

		//Generate keys
		//Generate H keys
		KeyGenerator generator_H(this->params);
		generator_H.generate();
		this->publicKey_H = generator_H.public_key();
		this->secretKey_H = generator_H.secret_key();
		//Generate evaluation keys
		this->evaluationKey = new EvaluationKeys(generator_H.evaluation_keys());
		//Generate MU key
		KeyGenerator generator_MU(this->params);
		generator_MU.generate();
		this->secretKey_MU = generator_MU.secret_key();
		//Generate SPU key
		seal::util::sub_poly_poly(this->secretKey_H, this->secretKey_MU, coeff_count, coeff_uint64_count, this->secretKey_SPU);
		//Set Encoder
		this->encoder = new BalancedEncoder(this->params.plain_modulus());
		//Set Encryptor
		this->encryptor = new Encryptor(this->params, this->publicKey_H);
		//Retrive normal noise
		// XXX Is the E recovered correctly?
		//return set_poly_coeffs_normal(noise.get());
		this->e_SPU = this->encryptor->getE();
		this->e_MU = this->encryptor->getE();
	};

	BigPoly The_CI::enc(const uint64_t &plainText){
		return this->encryptor->encrypt(this->encoder->encode(plainText));
	};
};
