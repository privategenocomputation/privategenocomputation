#ifndef THE_U_H
#define THE_U_H

//#include "seal"

namespace the{
	class The_U{

		public:
			The_U(const EncryptionParameters &params, const BigPoly &secretKey_U, const BigPoly &evaluationKey, const BigPoly &e_U);
			BigPoly add(const BigPoly &cypherText_1, const BigPoly &cypherText_2);
			BigPoly mult(const BigPoly &cypherText_1, const BigPoly &cypherText_2);
			BigPoly shareDec_U(const BigPoly &secretKey_U, const BigPoly &cypherText);
			BigPoly shareDec_U(const BigPoly &cypherText);
			BigPoly combine(const BigPoly &cypherText_SPU, const BigPoly &cypherText_MU);

		private:
			EcryptionParameters params;
			BigPoly evaluationKey;
			BigPoly secretKey_U;
			BigPoly e_U;
	};
}

#endif // THE_H
