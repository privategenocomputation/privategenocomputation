#ifndef SEAL_DECRYPTOR_H
#define SEAL_DECRYPTOR_H

#include "encryptionparams.h"
#include "util/modulus.h"
#include "util/polymodulus.h"
#include "bigpolyarray.h"

namespace seal
{
    /**
     Decrypts BigPolyArray objects into BigPoly objects. Constructing an Decryptor requires the encryption
     parameters (set through an EncryptionParameters object) and the secret key. The public and evaluation keys are not needed
     for decryption.
     */
    class DecryptorTK
    {
    public:
        /**
         Creates an Decryptor instance initialized with the specified encryption parameters and secret key.
         
         @param[in] parms The encryption parameters
         @param[in] secret_key The secret key
         @throws std::invalid_argument if encryption parameters or secret key are not valid
         @see EncryptionParameters for more details on valid encryption parameters.
         */
        DecryptorTK(const EncryptionParameters &parms, const BigPoly &secret_key);
        
        /**
         Decrypts an FV ciphertext and stores the result in the destination parameter.
         
         @param[in] encrypted The ciphertext to decrypt
         @param[out] destination The plaintext to overwrite with the decrypted ciphertext
         @throws std::invalid_argument if the ciphertext is not a valid ciphertext for the encryption parameters
         @throws std::logic_error If destination is an alias but needs to be resized
         */
        void decryptMU(const BigPolyArray &encrypted, BigPoly &destination, BigPoly &secretkeySPU, BigPoly &secretkeyH);
        /**
         Decrypts an BigPolyArray and returns the result.
         
         @param[in] encrypted The ciphertext to decrypt
         @throws std::invalid_argument if the ciphertext is not a valid ciphertext for the encryption parameters
         */
        
        /**
         Returns the secret key used by the Decryptor.
         */
        const BigPoly &secret_key() const
        {
            return secret_key_;
        }
        
    private:
        DecryptorTK(const DecryptorTK &copy) = delete;
        
        DecryptorTK &operator =(const DecryptorTK &assign) = delete;
        
        void compute_secret_key_array(int max_power);
        
        void set_poly_coeffs_normal(std::uint64_t *poly, UniformRandomGenerator *random) const;
        
        BigPoly poly_modulus_;
        
        BigUInt coeff_modulus_;
        
        BigUInt plain_modulus_;
        
        BigUInt upper_half_threshold_;
        
        BigUInt upper_half_increment_;
        
        BigUInt coeff_div_plain_modulus_;
        
        BigUInt coeff_div_plain_modulus_div_two_;
        
        BigPoly secret_key_;
        
        int orig_plain_modulus_bit_count_;
        
        util::PolyModulus polymod_;
        
        util::Modulus mod_;
        
        BigPolyArray secret_key_array_;
        
        double noise_standard_deviation_;
        
        double noise_max_deviation_;
    };
}

#endif // SEAL_DECRYPTOR_H
