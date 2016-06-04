#include "THE_CI.h"
#include "seal.h"
#include "bigpolyarith.h"

namespace the{
	void The_CI::gen(const EncryptionParameters &params){
		this->params = params;

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
		BigPolyArith bpa;
		this->secretKey_SPU = bpa.sub(this->secretKey_H, this->secretKey_MU);
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
