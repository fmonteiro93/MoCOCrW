/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
#pragma once

#include "key.h"
#include "openssl_wrap.h"
#include "padding_mode.h"
#include "x509.h"

namespace mococrw {

/**
 * This class represents a set of Signature utilities.
 */
class SignatureUtils
{
public:
    SignatureUtils() = delete;

private:

    enum class OperationType{ Sign, Verify};

    static const int c_defaultSaltLength = 20;

    /**
     * @brief Returns the hashing function for a given padding configuration
     *
     * Helper function.
     *
     * @param padding The padding mode
     * @throw MoCOCrWException if the padding mode isn't supported
     */
    static openssl::DigestTypes getHashing(const RSAPadding &padding);

    /**
     * @brief Digests a message
     *
     * Digests a message using a given algorithm.
     *
     * @param msg The message to be digested
     * @param algorithm The algorithm to be used in the digest operation
     * @throw MoCOCrWException if the algorithm isn't supported or the digest fails
     */
    static std::vector<uint8_t> digestMessage(const std::string &message,
                                              const openssl::DigestTypes &algorithm);

    /*
     * Set up an EVP_PKEY_CTX for ECC-based signature and verification operations
     */
    static void setUpContext(EVP_PKEY_CTX *ctx,
                             const OperationType &operation);

    /*
     * Set up an EVP_PKEY_CTX for RSA-based signature and verification operations
     */
    static void setUpContext(EVP_PKEY_CTX *ctx,
                             const RSAPadding &padding,
                             const OperationType &operation);

    /*
     * Performs the actual OpenSSL sign operation based on a context and a message digest.
     * Returns the signed message in @signedMessage
     */
    static void create(EVP_PKEY_CTX *ctx,
                       const std::vector<uint8_t> &messageDigest,
                       std::vector<uint8_t> &signedMessage);

    /*
     * Performs the actual OpenSSL verification operation based on a signature and a message digest.
     * Propagates the OpenSSLException in case of failure.
     */
    static void verify(EVP_PKEY_CTX *ctx,
                       const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &messageDigest);


public:
    /**
     * This class defines an interface to sign and verify messages using ECC keys and certificates.
     */
    class ECC
    {
    public:
        ECC() = delete;

        /**
         * @brief Create an ECC signature
         *
         * Creates an ECC signature for a plain text message based on a given private key.
         *
         * @param privateKey The private key to be used in the signature
         * @param message The message to be hashed and signed
         * @return The created signature of the message
         * @throw MoCOCrWException if the sign operation fails.
         */
        static std::vector<uint8_t> create(AsymmetricPrivateKey &privateKey,
                                           const std::string &message);
        /**
         * @brief Create an ECC signature
         *
         * Creates an ECC signature for a message digest based on a given private key.
         *
         * @param privateKey The private key to be used in the signature
         * @param messageDigest The message digest
         * @return The created ECC signature of the message
         * @throw MoCOCrWException if the sign operation fails.
         */
        static std::vector<uint8_t> create(AsymmetricPrivateKey &privateKey,
                                           const std::vector<uint8_t> &messageDigest);

        /**
         * @brief Verify a signature (ECC)
         *
         * Verifies a signature based on the signed message and a given public key and padding mode.
         *
         * @param publicKey The public key to be used in the verification
         * @param signature The signature to be verified
         * @param message The plain text message the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(AsymmetricPublicKey &publicKey,
                           const std::vector<uint8_t> &signature,
                           const std::string &message);

        /**
         * @brief Verify a signature (ECC)
         *
         * Verifies a signature based on the message digest and a given public key and padding mode.
         *
         * @param publicKey The public key to be used in the verification
         * @param signature The signature to be verified
         * @param messageDigest The message digest the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(AsymmetricPublicKey &publicKey,
                           const std::vector<uint8_t> &signature,
                           const std::vector<uint8_t> &messageDigest);

        /**
         * @brief Verify a signature (ECC)
         *
         * Verifies a signature based on the signed message and a given X509 certificate.
         *
         * @param certificate A x509 certificate from which the public key will be extracted
         * @param signature The signature to be verified
         * @param message The plain text message the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(const X509Certificate &certificate,
                           const std::vector<uint8_t> &signature,
                           const std::string &message);

        /**
         * @brief Verify a signature (ECC)
         *
         * Verifies a signature based on the message digest and a given X509 certificate.
         *
         * @param certificate A x509 certificate from which the public key will be extracted
         * @param signature The signature to be verified
         * @param messageDigest The message digest the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(const X509Certificate &certificate,
                           const std::vector<uint8_t> &signature,
                           const std::vector<uint8_t> &messageDigest);
    };

    /**
     * This class defines an interface to sign and verify messages using ECC keys and certificates.
     */
    class RSA
    {
    public:
        RSA() = delete;

        /**
         * @brief Create an RSA signature
         *
         * Creates an RSA signature for a plain text message based on a given private key and padding mode.
         *
         * @param privateKey The private key to be used in the signature
         * @param padding The padding mode
         * @param message The message to be hashed and signed
         * @return The created signature of the message
         * @throw MoCOCrWException if the sign operation fails.
         */
        static std::vector<uint8_t> create(AsymmetricPrivateKey &privateKey,
                                           const RSAPadding &padding,
                                           const std::string &message);

        /**
         * @brief Create an RSA signature
         *
         * Creates an RSA signature for a message digest based on a given private key and padding mode.
         *
         * @param privateKey The private key to be used in the signature
         * @param padding The padding mode
         * @param messageDigest The message digest
         * @return The created signature of the message
         * @throw MoCOCrWException if the sign operation fails.
         */
        static std::vector<uint8_t> create(AsymmetricPrivateKey &privateKey,
                                           const RSAPadding &padding,
                                           const std::vector<uint8_t> &messageDigest);

        /**
         * @brief Verify a signature
         *
         * Verifies a signature based on the signed message and a given public key and padding mode.
         *
         * @param publicKey The public key to be used in the verification
         * @param padding The padding mode
         * @param signature The signature to be verified
         * @param message The plain text message the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(AsymmetricPublicKey &publicKey,
                           const RSAPadding &padding,
                           const std::vector<uint8_t> &signature,
                           const std::string &message);

        /**
         * @brief Verify a signature
         *
         * Verifies a signature based on the message digest and a given public key and padding mode.
         *
         * @param publicKey The public key to be used in the verification
         * @param padding The padding mode
         * @param signature The signature to be verified
         * @param messageDigest The message digest the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(AsymmetricPublicKey &publicKey,
                           const RSAPadding &padding,
                           const std::vector<uint8_t> &signature,
                           const std::vector<uint8_t> &messageDigest);

        /**
         * @brief Verify a signature
         *
         * Verifies a signature based on the signed message and a given X509 certificate and padding
         * mode.
         *
         * @param certificate A x509 certificate from which the public key will be extracted
         * @param padding The padding mode
         * @param signature The signature to be verified
         * @param message The plain text message the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(const X509Certificate &certificate,
                           const RSAPadding &padding,
                           const std::vector<uint8_t> &signature,
                           const std::string &message);

        /**
         * @brief Verify a signature
         *
         * Verifies a signature based on the message digest and a given X509 certificate and padding
         * mode.
         *
         * @param certificate A x509 certificate from which the public key will be extracted
         * @param padding The padding mode
         * @param signature The signature to be verified
         * @param messageDigest The message digest the signature is verified with
         * @throw MoCOCrWException if the verification fails.
         */
        static void verify(const X509Certificate &certificate,
                           const RSAPadding &padding,
                           const std::vector<uint8_t> &signature,
                           const std::vector<uint8_t> &messageDigest);
    };

    friend class ECC;
    friend class RSA;
};

} // namespace mococrw
