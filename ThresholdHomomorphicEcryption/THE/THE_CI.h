#ifndef THE_CI_H
#define THE_CI_H

//#include "seal"

namespace the{
	class The_CI{

		public:
			The_CI();
			void gen(const EncryptionParameters &parms);
			BigPoly enc(const BigPoly &publicKey, const BigPoly &plainText);
			BigPoly enc(const BigPoly &plainText);

		private:
			EcryptionParameters params;
			BigPoly publicKey_H;
			BigPoly secretKey_H;
			BigPoly secretKey_SPU;
			BigPoly secretKey_MU;
			BigPoly e_SPU;
			BigPoly e_MU;
	};
}

#endif // THE_H_CI
