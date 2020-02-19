/*
 *
 * Copyright 2019 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_generator.h"

#include <iterator>
#include <numeric>
#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/mock_intel_architectural_enclave_interface.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/mock_hardware_interface.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/thread.h"

namespace asylo {
namespace {

using asylo::sgx::kReportdataSize;
using asylo::sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority;
using asylo::sgx::kValidMiscselectBitmask;
using asylo::sgx::MockHardwareInterface;
using asylo::sgx::MockIntelArchitecturalEnclaveInterface;
using asylo::sgx::Report;
using asylo::sgx::Reportdata;
using asylo::sgx::Targetinfo;
using ::testing::_;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::Test;

class SgxIntelEcdsaQeRemoteAssertionGeneratorTests : public testing::Test {
 protected:
  AssertionDescription CreateValidAssertionDescription() const {
    AssertionDescription description;
    description.set_authority_type(kSgxIntelEcdsaQeRemoteAssertionAuthority);
    description.set_identity_type(CODE_IDENTITY);
    return description;
  }

  Targetinfo CreateFakeTargetInfo() const {
    Targetinfo info = TrivialRandomObject<Targetinfo>();
    info.reserved1.fill(0);
    info.reserved2.fill(0);
    info.reserved3.fill(0);
    info.miscselect &= kValidMiscselectBitmask;
    info.attributes = {};
    return info;
  }

  static const char *const kValidConfig;
  static const uint8_t kAadUuid[kAdditionalAuthenticatedDataUuidSize];
  static const uint8_t kAadPurpose[kAdditionalAuthenticatedDataPurposeSize];

  // Owned by |generator_|, which only accepts a unique_ptr.
  MockIntelArchitecturalEnclaveInterface *mock_intel_enclaves_ =
      new MockIntelArchitecturalEnclaveInterface;
  // Owned by |generator_|, which only accepts a unique_ptr.
  MockHardwareInterface *mock_hardware_interface_ = new MockHardwareInterface;
  SgxIntelEcdsaQeRemoteAssertionGenerator generator_{
      absl::make_unique<AdditionalAuthenticatedDataGenerator>(kAadUuid,
                                                              kAadPurpose),
      absl::WrapUnique(mock_intel_enclaves_),
      absl::WrapUnique(mock_hardware_interface_)};
};

const char *const SgxIntelEcdsaQeRemoteAssertionGeneratorTests::kValidConfig =
    SgxIntelEcdsaQeRemoteAssertionGenerator::kDefaultConfig;
const uint8_t SgxIntelEcdsaQeRemoteAssertionGeneratorTests::kAadUuid[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1};
const uint8_t SgxIntelEcdsaQeRemoteAssertionGeneratorTests::kAadPurpose[] = {
    8, 6, 7, 5, 3, 0, 9, 9, 8, 6, 7, 5, 3, 0, 9, 9};

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       GeneratorFoundInStaticMap) {
  auto authority_id_result = EnclaveAssertionAuthority::GenerateAuthorityId(
      CODE_IDENTITY, kSgxIntelEcdsaQeRemoteAssertionAuthority);

  ASSERT_THAT(authority_id_result, IsOk());
  ASSERT_NE(AssertionGeneratorMap::GetValue(authority_id_result.ValueOrDie()),
            AssertionGeneratorMap::value_end());
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests, InitializeWorksOnce) {
  EXPECT_FALSE(generator_.IsInitialized());
  EXPECT_THAT(generator_.Initialize(kValidConfig), IsOk());
  EXPECT_TRUE(generator_.IsInitialized());
  EXPECT_THAT(generator_.Initialize(kValidConfig),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       InitializeFailsWithBadConfig) {
  EXPECT_THAT(generator_.Initialize("BAD CONFIG !@#$%^"),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests, IdentityType) {
  EXPECT_THAT(generator_.IdentityType(), Eq(CODE_IDENTITY));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests, AuthorityType) {
  EXPECT_THAT(generator_.AuthorityType(),
              Eq(kSgxIntelEcdsaQeRemoteAssertionAuthority));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       CreateAssertionOfferSuccess) {
  ASSERT_THAT(generator_.Initialize(kValidConfig), IsOk());

  AssertionOffer assertion_offer;
  ASSERT_THAT(generator_.CreateAssertionOffer(&assertion_offer), IsOk());
  EXPECT_THAT(assertion_offer.description(),
              EqualsProto(CreateValidAssertionDescription()));
  EXPECT_FALSE(assertion_offer.has_additional_information());
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       CreateAssertionOfferFailsIfNotInitialized) {
  ASSERT_FALSE(generator_.IsInitialized());
  AssertionOffer assertion_offer;
  EXPECT_THAT(generator_.CreateAssertionOffer(&assertion_offer),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests, CanGenerateSuccess) {
  ASSERT_THAT(generator_.Initialize(kValidConfig), IsOk());
  AssertionRequest request;
  *request.mutable_description() = CreateValidAssertionDescription();
  EXPECT_THAT(generator_.CanGenerate(request), IsOkAndHolds(true));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       CanGenerateFailsIfNotInitialized) {
  ASSERT_FALSE(generator_.IsInitialized());
  EXPECT_THAT(generator_.CanGenerate(AssertionRequest{}),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       CanGenerateFailsForIncompatibleDescription) {
  ASSERT_THAT(generator_.Initialize(kValidConfig), IsOk());
  AssertionRequest request;

  *request.mutable_description() = CreateValidAssertionDescription();
  request.mutable_description()->mutable_authority_type()->append("nope");
  EXPECT_THAT(generator_.CanGenerate(request), IsOkAndHolds(false));

  *request.mutable_description() = CreateValidAssertionDescription();
  request.mutable_description()->set_identity_type(UNKNOWN_IDENTITY);
  EXPECT_THAT(generator_.CanGenerate(request), IsOkAndHolds(false));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests, GenerateSuccess) {
  const char kData[] = "Data whose hash is included in the assertion.";
  constexpr uint8_t kDataSha256[] = {
      0xb1, 0x0f, 0x7e, 0xc1, 0x01, 0x63, 0x92, 0xaf, 0xa7, 0x3f, 0x94,
      0x9b, 0x68, 0xc7, 0xd4, 0xaa, 0x61, 0x95, 0x64, 0x10, 0x08, 0xf0,
      0x00, 0x75, 0xb9, 0x3b, 0xa4, 0x8f, 0x66, 0x50, 0x9f, 0x38};

  Reportdata expected_report_data;
  expected_report_data.data.assign(kDataSha256);
  expected_report_data.data.replace(sizeof(kDataSha256), kAadPurpose);
  expected_report_data.data.replace(sizeof(kDataSha256) + sizeof(kAadPurpose),
                                    kAadUuid);

  ASSERT_THAT(generator_.Initialize(kValidConfig), IsOk());
  AssertionRequest request;
  *request.mutable_description() = CreateValidAssertionDescription();

  const Targetinfo kTargetinfo = CreateFakeTargetInfo();
  EXPECT_CALL(*mock_intel_enclaves_, GetQeTargetinfo())
      .WillOnce(Return(kTargetinfo));

  const Report kReport = TrivialRandomObject<Report>();
  EXPECT_CALL(*mock_hardware_interface_,
              GetReport(TrivialObjectEq(kTargetinfo),
                        TrivialObjectEq(expected_report_data)))
      .WillOnce(Return(kReport));

  std::vector<uint8_t> fake_quote(123);
  std::iota(fake_quote.begin(), fake_quote.end(), 0);
  EXPECT_CALL(*mock_intel_enclaves_, GetQeQuote(TrivialObjectEq(kReport)))
      .WillOnce(Return(fake_quote));

  Assertion assertion;
  ASSERT_THAT(generator_.Generate(kData, request, &assertion), IsOk());
  EXPECT_THAT(assertion.description(),
              EqualsProto(CreateValidAssertionDescription()));
  EXPECT_THAT(assertion.assertion(), ElementsAreArray(fake_quote));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       GenerateFailsIfNotInitialized) {
  ASSERT_FALSE(generator_.IsInitialized());
  Assertion assertion;
  EXPECT_THAT(
      generator_.Generate(/*user_data=*/"", AssertionRequest{}, &assertion),
      StatusIs(error::GoogleError::FAILED_PRECONDITION));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       GenerateFailsForIncompatibleDescription) {
  ASSERT_THAT(generator_.Initialize(kValidConfig), IsOk());
  AssertionRequest request;
  Assertion assertion;

  *request.mutable_description() = CreateValidAssertionDescription();
  request.mutable_description()->mutable_authority_type()->append("nope");
  EXPECT_THAT(
      generator_.Generate(/*user_data=*/"", AssertionRequest{}, &assertion),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));

  *request.mutable_description() = CreateValidAssertionDescription();
  request.mutable_description()->set_identity_type(UNKNOWN_IDENTITY);
  EXPECT_THAT(
      generator_.Generate(/*user_data=*/"", AssertionRequest{}, &assertion),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionGeneratorTests,
       InitializeSucceedsOnceFromMultipleThreads) {
  constexpr int kNumThreads = 10;

  std::atomic<int> success_count(0);
  std::vector<Thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([this, &success_count] {
      success_count += generator_.Initialize(kValidConfig).ok();
    });
  }
  for (auto &thread : threads) {
    thread.Join();
  }
  EXPECT_THAT(success_count.load(), Eq(1));
}

}  // namespace
}  // namespace asylo
