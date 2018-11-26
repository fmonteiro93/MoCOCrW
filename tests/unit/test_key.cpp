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
    mococrw::AsymmetricKeypair _keyPair = AsymmetricKeypair::generate();
    mococrw::AsymmetricKeypair _keyPair2 = AsymmetricKeypair::generate();
};

void KeyHandlingTests::SetUp() {
    _keyPair = AsymmetricKeypair::generate();
    _keyPair2 = AsymmetricKeypair::generate();
}

TEST_F(KeyHandlingTests, testGeneratedKeyIsNotNull)
{
    ASSERT_THAT(_keyPair.internal(), NotNull());
}

TEST_F(KeyHandlingTests, testPublicKeyPemIsReproducible)
{
    const auto pemOfKey = _keyPair.publicKeyToPem();
    const auto pemOfKey2 = _keyPair.publicKeyToPem();

    ASSERT_EQ(pemOfKey, pemOfKey2);
}

TEST_F(KeyHandlingTests, testPubKeyFromSavedPemIsSameAsOriginalInOpenSSLObject)
{
    const auto pemOfPubkey = _keyPair.publicKeyToPem();

    auto parsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    ASSERT_EQ(_keyPair, parsedKey);
}

TEST_F(KeyHandlingTests, testPubkeyFromSavedPemIsSameAsOriginalInPEM)
{
    const auto pemOfKey = _keyPair.publicKeyToPem();

    auto parsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfKey);
    ASSERT_EQ(pemOfKey, parsedKey.publicKeyToPem());
}

TEST_F(KeyHandlingTests, testPrivKeyFromSavedPemIsSameAsOriginal)
{
    const auto pemOfPubKey = _keyPair.publicKeyToPem();
    const auto pemOfPrivateKey = _keyPair.privateKeyToPem("secret");

    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(pemOfPubKey, retrievedKeyPair.publicKeyToPem());
}

TEST_F(KeyHandlingTests, testBothGeneratedKeysNotTheSame)
{
    ASSERT_NE(_keyPair, _keyPair2);
}

TEST_F(KeyHandlingTests, testThrowsWhenReadingPrivateKeyUsingWrongKey)
{
    const auto pemOfPrivateKey = _keyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);
}

TEST_F(KeyHandlingTests, ecc_adoc_test)
{
    ECCSpec spec{};
    auto key = AsymmetricKeypair::generate(spec);
    std::cout << key.privateKeyToPem("alice") << std::endl;
    std::cout << "-------------------------------------------------------" << std::endl;
    std::cout << key.publicKeyToPem() << std::endl;

    auto key2 = AsymmetricKeypair::generate(spec);
    std::cout << key2.privateKeyToPem("pass") << std::endl;
    std::cout << "-------------------------------------------------------" << std::endl;
    std::cout << key2.publicKeyToPem() << std::endl;

//    auto retrievedKey = AsymmetricKeypair::readPrivateKeyFromPEM(key.privateKeyToPem(pass), pass);
//    std::cout << "-------------------------------------------------------" << std::endl;
//    std::cout << retrievedKey.privateKeyToPem("password") << std::endl;
//    std::cout << "-------------------------------------------------------" << std::endl;
//    std::cout << retrievedKey.publicKeyToPem() << std::endl;
//    if (retrievedKey == key)
//        ASSERT_EQ(true, true);
//    else
//        ASSERT_EQ(true, false);

}

/* Test the KeySpec and the generation of keys that way */

TEST(KeySpecTest, testGeneratingRSAKeyWithDefaultParameters)
{
    RSASpec spec{};

    auto keypair = spec.generate();
    ASSERT_THAT(keypair.internal(), NotNull());
}

TEST(KeySpecTest, testThatDefaultParametersAreSane)
{
    RSASpec spec{};
    ASSERT_THAT(spec.numberOfBits(), Eq(2048));

    RSASpec nonDefault{1024};
    ASSERT_THAT(nonDefault.numberOfBits(), Eq(1024));
}

