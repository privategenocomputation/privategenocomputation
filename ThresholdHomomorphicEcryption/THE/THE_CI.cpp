#include "THE_CI.h"
#include "seal.h"
#include "bigpolyarith.h"

#include <iostream>

namespace the{
	void The_CI::gen(const EncryptionParameters &params){
		this->params = params;

		//Generate keys
		//Generate H keys
		KeyGenerator generator_H(this->params);
		generator_H.generate();
		//this->publicKey_H = generator_H.public_key();
		this->secretKey_H = generator_H.secret_key();
		//Generate evaluation keys
		// XXX is it done correctly?
		this->evaluationKey = new EvaluationKeys(generator_H.evaluation_keys());
		//Generate MU key
		KeyGenerator generator_MU(this->params);
		generator_MU.generate();
		this->secretKey_MU = generator_MU.secret_key();
		//Generate SPU key
		BigPolyArith bpa;
		this->secretKey_SPU = bpa.sub(generator_H.public_key(), this->secretKey_MU);
//std::cout << "is equal? " << (this->secretKey_MU == generator_MU.secret_key()) << std::endl;
//std::cout << "this->secretKey_MU: " << this->secretKey_MU.to_string() << std::endl;
//std::cout/* << "generator_MU.secret_key(): " */<< generator_MU.secret_key().to_string() << std::endl;
std::cout << "decMU1" << std::endl;
Decryptor decMU1(params, generator_MU.secret_key());
std::cout << "decMU2" << std::endl;
Decryptor decMU2(this->params, this->secretKey_MU);
//std::cout << "decSPU" << std::endl;
//Decryptor decSPU(this->params, this->secretKey_SPU);
		//Set Encoder
		this->encoder = new BalancedEncoder(this->params.plain_modulus());
		//Set Encryptor
//std::cout << "prout!" << std::endl;
		this->encryptor = new Encryptor(this->params, generator_H.public_key());
//std::cout << "bitch, plz!" << std::endl;
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
