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
    mococrw::AsymmetricKeypair _rsaKeyPair = AsymmetricKeypair::generateRSA();
    mococrw::AsymmetricKeypair _rsaKeyPair2 = AsymmetricKeypair::generateRSA();
    mococrw::AsymmetricKeypair _eccKeyPairDefault = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairDefault2 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairSect571r1 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairSecp521r1 = AsymmetricKeypair::generateECC();
};

void KeyHandlingTests::SetUp() {
    _rsaKeyPair = AsymmetricKeypair::generateRSA();
    _rsaKeyPair2 = AsymmetricKeypair::generateRSA();

    _eccKeyPairDefault = AsymmetricKeypair::generateECC();
    _eccKeyPairDefault2 = AsymmetricKeypair::generateECC();

    _eccKeyPairSect571r1 = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::SECT_571r1});
    _eccKeyPairSecp521r1 = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::SECP_521r1});
}

TEST_F(KeyHandlingTests, testGeneratedKeyIsNotNull)
{
    ASSERT_THAT(_rsaKeyPair.internal(), NotNull());
    ASSERT_THAT(_rsaKeyPair2.internal(), NotNull());

    ASSERT_THAT(_eccKeyPairDefault.internal(), NotNull());
    ASSERT_THAT(_eccKeyPairDefault2.internal(), NotNull());

    ASSERT_THAT(_eccKeyPairSecp521r1.internal(), NotNull());
    ASSERT_THAT(_eccKeyPairSect571r1.internal(), NotNull());

}

TEST_F(KeyHandlingTests, testPublicKeyPemIsReproducible)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfKey2 = _rsaKeyPair.publicKeyToPem();

    const auto pemOfEccKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfEccKey2 = _eccKeyPairDefault.publicKeyToPem();

    const auto pemOfSectEccKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfSectEccKey2 = _eccKeyPairSect571r1.publicKeyToPem();

    ASSERT_EQ(pemOfKey, pemOfKey2);
    ASSERT_EQ(pemOfEccKey, pemOfEccKey2);
    ASSERT_EQ(pemOfSectEccKey, pemOfSectEccKey2);
}

TEST_F(KeyHandlingTests, testPubKeyFromSavedPemIsSameAsOriginalInOpenSSLObject)
{
    const auto pemOfPubkey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfEccPubkey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfSecpEccPubkey = _eccKeyPairSecp521r1.publicKeyToPem();

    auto rsaParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    auto eccParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccPubkey);
    auto eccSecpParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfSecpEccPubkey);

    ASSERT_EQ(_rsaKeyPair, rsaParsedKey);
    ASSERT_EQ(_eccKeyPairDefault, eccParsedKey);
    ASSERT_EQ(_eccKeyPairSecp521r1, eccSecpParsedKey);
}

TEST_F(KeyHandlingTests, testPubkeyFromSavedPemIsSameAsOriginalInPEM)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfEccKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfSectEccKey = _eccKeyPairSect571r1.publicKeyToPem();

    auto parsedRsaKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfKey);
    auto parsedEccKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccKey);
    auto parsedSectEccKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfSectEccKey);

    ASSERT_EQ(pemOfKey, parsedRsaKey.publicKeyToPem());
    ASSERT_EQ(pemOfEccKey, parsedEccKey.publicKeyToPem());
    ASSERT_EQ(pemOfSectEccKey, parsedSectEccKey.publicKeyToPem());
}

TEST_F(KeyHandlingTests, testPrivKeyFromSavedPemIsSameAsOriginal)
{
    const auto pemOfPubKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");

    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(pemOfPubKey, retrievedKeyPair.publicKeyToPem());

    const auto pemOfEccPubKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfEccPrivateKey = _eccKeyPairDefault.privateKeyToPem("password");

    auto retrievedEccKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "password");
    ASSERT_EQ(pemOfEccPubKey, retrievedEccKeyPair.publicKeyToPem());

    const auto pemOfSectEccPubKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfSectEccPrivateKey = _eccKeyPairSect571r1.privateKeyToPem("santa");

    auto retrievedSectEccKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSectEccPrivateKey, "santa");
    ASSERT_EQ(pemOfSectEccPubKey, retrievedSectEccKeyPair.publicKeyToPem());
}

TEST_F(KeyHandlingTests, testBothGeneratedKeysNotTheSame)
{
    ASSERT_NE(_rsaKeyPair, _rsaKeyPair2);

    ASSERT_NE(_eccKeyPairDefault, _eccKeyPairDefault2);
}

TEST_F(KeyHandlingTests, testThrowsWhenReadingPrivateKeyUsingWrongKey)
{
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);

    const auto pemOfEccPrivateKey = _eccKeyPairDefault.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);

    const auto pemOfSecpEccPrivateKey = _eccKeyPairSecp521r1.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSecpEccPrivateKey, "santa"),
                 mococrw::OpenSSLException);
}

TEST_F(KeyHandlingTests, testKeyTypeChecking)
{
    EXPECT_EQ(_eccKeyPairDefault.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_rsaKeyPair.getType(), AsymmetricKey::KeyTypes::RSA);
    EXPECT_EQ(_eccKeyPairSecp521r1.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_eccKeyPairSect571r1.getType(), AsymmetricKey::KeyTypes::ECC);
}

TEST_F(KeyHandlingTests, testGetEccCurve)
{
    EXPECT_EQ(_eccKeyPairDefault.getCurve(), openssl::ellipticCurveNid::PRIME_256v1);
    EXPECT_EQ(_eccKeyPairSect571r1.getCurve(), openssl::ellipticCurveNid::SECT_571r1);
    EXPECT_EQ(_eccKeyPairSecp521r1.getCurve(), openssl::ellipticCurveNid::SECP_521r1);
}

TEST_F(KeyHandlingTests, testGetCurveWithRsaKey)
{
    ASSERT_THROW(_rsaKeyPair.getCurve(), mococrw::MoCOCrWException);
    ASSERT_THROW(_rsaKeyPair2.getCurve(), mococrw::MoCOCrWException);
}

TEST_F(KeyHandlingTests, testGetSize)
{
    EXPECT_EQ(_rsaKeyPair.getKeySize(), 2048);
    EXPECT_EQ(_eccKeyPairDefault.getKeySize(), 256);
    EXPECT_EQ(_eccKeyPairSecp521r1.getKeySize(), 521);
    EXPECT_EQ(_eccKeyPairSect571r1.getKeySize(), 570);
    auto rsaKey1024 = AsymmetricKeypair::generate(mococrw::RSASpec{1024});
    EXPECT_EQ(rsaKey1024.getKeySize(), 1024);
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

