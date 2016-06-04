#ifndef THE_U_H
#define THE_U_H

#include "seal.h"
using namespace seal;
using namespace seal::util;

namespace the{
	class The_U{

		public:
			The_U(const EncryptionParameters &params, const BigPoly &secretKey_U, const EvaluationKeys &evaluationKey, const BigPoly &e_U):params(params),secretKey_U(secretKey_U),e_U(e_U){
				// FIXME
				//this->evaluationKey = &evaluationKey;
				//this->evaluator = new Evaluator(this->params, &(this->evaluationKey));
			};
			BigPoly add(const BigPoly &cypherText_1, const BigPoly &cypherText_2);
			BigPoly mult(const BigPoly &cypherText_1, const BigPoly &cypherText_2);
			BigPoly shareDec_U(const BigPoly &secretKey_U, const BigPoly &cypherText);
			BigPoly shareDec_U(const BigPoly &cypherText);
			uint64_t combine(const BigPoly &cypherText_SPU, const BigPoly &cypherText_MU);

		private:
			EncryptionParameters params;
			BigPoly secretKey_U;
			BigPoly e_U;
			EvaluationKeys *evaluationKey;
			Evaluator *evaluator;
	};
};
#endif // THE_H
