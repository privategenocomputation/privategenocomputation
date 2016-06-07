#ifndef THE_CI_H
#define THE_CI_H
#include "seal.h"

using namespace seal;

namespace the{
	class The_CI{

		public:
			The_CI(){};
			void gen(const EncryptionParameters &params);
			BigPoly enc(const uint64_t &plainText);

			// Getters
			inline EncryptionParameters getParams(){return this->params;};
			//inline BigPoly getPulicKey_H(){return this->publicKey_H;};
			inline BigPoly getSecretKey_SPU(){return this->secretKey_SPU;};
			inline BigPoly getSecretKey_MU(){return this->secretKey_MU;};
			inline EvaluationKeys getEvaluationKey(){return *(this->evaluationKey);};
			inline BigPoly getE_SPU(){return this->e_SPU;};
			inline BigPoly getE_MU(){return this->e_MU;};

		private:
			EncryptionParameters params;
			BalancedEncoder *encoder;
			Encryptor *encryptor;
			//BigPoly publicKey_H;
			BigPoly secretKey_H;
			BigPoly secretKey_SPU;
			BigPoly secretKey_MU;
			EvaluationKeys *evaluationKey;
			BigPoly e_SPU;
			BigPoly e_MU;
	};
};
#endif // THE_H_CI
