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
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "key.cpp"

using namespace mococrw;
using namespace ::testing;


class KeyHandlingTests : public ::testing::Test
{
public:
    void SetUp() override;
protected:
    mococrw::AsymmetricKeypair _rsaKeyPair = AsymmetricKeypair::generate();
    mococrw::AsymmetricKeypair _rsaKeyPair2 = AsymmetricKeypair::generate();
    mococrw::AsymmetricKeypair _eccKeyPair = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPair2 = AsymmetricKeypair::generateECC();
};

void KeyHandlingTests::SetUp() {
    _rsaKeyPair = AsymmetricKeypair::generate();
    _rsaKeyPair2 = AsymmetricKeypair::generate();
}

TEST_F(KeyHandlingTests, testGeneratedKeyIsNotNull)
{
    ASSERT_THAT(_rsaKeyPair.internal(), NotNull());
    ASSERT_THAT(_rsaKeyPair2.internal(), NotNull());

    ASSERT_THAT(_eccKeyPair.internal(), NotNull());
    ASSERT_THAT(_eccKeyPair2.internal(), NotNull());

}

TEST_F(KeyHandlingTests, testPublicKeyPemIsReproducible)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfKey2 = _rsaKeyPair.publicKeyToPem();

    const auto pemOfEccKey = _eccKeyPair.publicKeyToPem();
    const auto pemOfEccKey2 = _eccKeyPair.publicKeyToPem();

    ASSERT_EQ(pemOfKey, pemOfKey2);
    ASSERT_EQ(pemOfEccKey, pemOfEccKey2);

}

TEST_F(KeyHandlingTests, testPubKeyFromSavedPemIsSameAsOriginalInOpenSSLObject)
{
    const auto pemOfPubkey = _rsaKeyPair.publicKeyToPem();

    const auto pemOfEccPubkey = _eccKeyPair.publicKeyToPem();

    auto rsaParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    auto eccParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccPubkey);

    EXPECT_EQ(openssl::_EVP_PKEY_cmp(_eccKeyPair.internal(), eccParsedKey.internal()), true);


    ASSERT_EQ(_rsaKeyPair, rsaParsedKey);

    ASSERT_EQ(_eccKeyPair, eccParsedKey);

}

TEST_F(KeyHandlingTests, testPubkeyFromSavedPemIsSameAsOriginalInPEM)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfEccKey = _eccKeyPair.publicKeyToPem();


    auto parsedRsaKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfKey);
    auto parsedEccKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccKey);

    ASSERT_EQ(pemOfKey, parsedRsaKey.publicKeyToPem());
    ASSERT_EQ(pemOfEccKey, parsedEccKey.publicKeyToPem());

}

TEST_F(KeyHandlingTests, testPrivKeyFromSavedPemIsSameAsOriginal)
{
    const auto pemOfPubKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");

    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(pemOfPubKey, retrievedKeyPair.publicKeyToPem());

    const auto pemOfEccPubKey = _eccKeyPair.publicKeyToPem();
    const auto pemOfEccPrivateKey = _eccKeyPair.privateKeyToPem("password");

    auto retrievedEccKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "password");
    ASSERT_EQ(pemOfEccPubKey, retrievedEccKeyPair.publicKeyToPem());

}

TEST_F(KeyHandlingTests, testBothGeneratedKeysNotTheSame)
{
    ASSERT_NE(_rsaKeyPair, _rsaKeyPair2);

    ASSERT_NE(_eccKeyPair, _eccKeyPair2);
}

TEST_F(KeyHandlingTests, testThrowsWhenReadingPrivateKeyUsingWrongKey)
{
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);

    const auto pemOfEccPrivateKey = _eccKeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);
}

TEST_F(KeyHandlingTests, testKeyTypeChecking)
{
    EXPECT_EQ(_eccKeyPair.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_rsaKeyPair.getType(), AsymmetricKey::KeyTypes::RSA);
}

/* Test the KeySpec and the generation of keys that way */
TEST(KeySpecTest, testGeneratingRSAKeyWithDefaultParameters)
{
    RSASpec spec{};

    auto keypair = spec.generate();
    ASSERT_THAT(keypair.internal(), NotNull());
}

/* Test the KeySpec and the generation of keys that way */
TEST(KeySpecTest, testGeneratingEccKeyWithDefaultParameters)
{
    ECCSpec spec{};

    auto keypair = spec.generate();
    ASSERT_THAT(keypair.internal(), NotNull());
}

TEST(KeySpecTest, testThatDefaultParametersAreSane)
{
    RSASpec spec{};
    ASSERT_THAT(spec.numberOfBits(), Eq(2048));

    RSASpec nonDefault{1024};
    ASSERT_THAT(nonDefault.numberOfBits(), Eq(1024));

    ECCSpec defaultEccSpec{};
    ASSERT_EQ(defaultEccSpec.curve(), openssl::ellipticCurveNid::PRIME_256v1);

    ECCSpec nonDefaultEccSpec{openssl::ellipticCurveNid::SECT_283k1};
    ASSERT_EQ(nonDefaultEccSpec.curve(), openssl::ellipticCurveNid::SECT_283k1);
}

