#ifndef SEAL_DecryptorCombine_H
#define SEAL_DecryptorCombine_H

#include "encryptionparams.h"
#include "util/modulus.h"
#include "util/polymodulus.h"
#include "bigpolyarray.h"

namespace seal
{
    /**
    Decrypts BigPolyArray objects into BigPoly objects. Constructing an DecryptorCombine requires the encryption
    parameters (set through an EncryptionParameters object) and the secret key. The public and evaluation keys are not needed
    for decryption.
    */
    class DecryptorCombine
    {
    public:
        /**
        Creates an DecryptorCombine instance initialized with the specified encryption parameters and secret key.

        @param[in] parms The encryption parameters
        @param[in] secret_key The secret key
        @throws std::invalid_argument if encryption parameters or secret key are not valid
        @see EncryptionParameters for more details on valid encryption parameters.
        */
        DecryptorCombine(const EncryptionParameters &parms);

        /**
        Decrypts an FV ciphertext and stores the result in the destination parameter.

        @param[in] encrypted The ciphertext to decrypt
        @param[out] destination The plaintext to overwrite with the decrypted ciphertext
        @throws std::invalid_argument if the ciphertext is not a valid ciphertext for the encryption parameters
        @throws std::logic_error If destination is an alias but needs to be resized
        */
        void decrypt(const BigPolyArray &encrypted, BigPoly &destination);

        /**
        Decrypts an BigPolyArray and returns the result.

        @param[in] encrypted The ciphertext to decrypt
        @throws std::invalid_argument if the ciphertext is not a valid ciphertext for the encryption parameters
        */
        BigPoly decrypt(const BigPolyArray &encrypted)
        {
            BigPoly result;
            decrypt(encrypted, result);
            return result;
        }

    private:
        DecryptorCombine(const DecryptorCombine &copy) = delete;

        DecryptorCombine &operator =(const DecryptorCombine &assign) = delete;


        BigPoly poly_modulus_;

        BigUInt coeff_modulus_;

        BigUInt plain_modulus_;

        BigUInt upper_half_threshold_;

        BigUInt upper_half_increment_;

        BigUInt coeff_div_plain_modulus_;

        BigUInt coeff_div_plain_modulus_div_two_;

        int orig_plain_modulus_bit_count_;

        util::PolyModulus polymod_;

        util::Modulus mod_;
    };
}

#endif // SEAL_DecryptorCombine_H
