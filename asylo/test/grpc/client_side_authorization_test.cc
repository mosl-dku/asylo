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

#include <string>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "asylo/client.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/sgx/secs_attributes.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/test/grpc/client_enclave.pb.h"
#include "asylo/test/grpc/messenger_server_impl.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "debug_key_mrsigner.h"

ABSL_FLAG(std::string, server_enclave_path, "", "Path to gRPC server enclave.");
ABSL_FLAG(std::string, client_enclave_path, "", "Path to gRPC client enclave.");

namespace asylo {
namespace {

using ::testing::NotNull;
using ::testing::Test;

constexpr char kClientName[] = "Client";

constexpr char kServerName[] = "Secure Server";

constexpr char kClientInput[] = "Random string?";

// Matches the server's configuration in the BUILD file.
constexpr uint32_t kExpectedServerIsvprodid = 1;
constexpr uint32_t kExpectedServerIsvsvn = 2;

constexpr char kHost[] = "[::1]";

class ClientSideAuthorizationTest : public Test {
 protected:
  static void SetUpTestSuite() {
    asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
    ASYLO_ASSERT_OK_AND_ASSIGN(manager_, asylo::EnclaveManager::Instance());
  }

  void SetUp() override {
    ASSERT_FALSE(absl::GetFlag(FLAGS_client_enclave_path).empty());
    asylo::SgxLoader client_loader(absl::GetFlag(FLAGS_client_enclave_path),
                                   /*debug=*/true);

    asylo::EnclaveConfig client_config;
    *client_config.add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();
    ASYLO_ASSERT_OK(
        manager_->LoadEnclave(kClientName, client_loader, client_config));
    client_enclave_ = manager_->GetClient(kClientName);
    ASSERT_THAT(client_enclave_, NotNull());

    ASSERT_FALSE(absl::GetFlag(FLAGS_server_enclave_path).empty());
    asylo::SgxLoader server_loader(absl::GetFlag(FLAGS_server_enclave_path),
                                   /*debug=*/true);

    asylo::EnclaveConfig server_config;
    server_config.MutableExtension(server_input_config)->set_host(kHost);
    server_config.MutableExtension(server_input_config)->set_port(0);
    *server_config.add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();
    ASYLO_ASSERT_OK(
        manager_->LoadEnclave(kServerName, server_loader, server_config));
    server_enclave_ = manager_->GetClient(kServerName);
    ASSERT_THAT(server_enclave_, NotNull());

    EnclaveInput input;
    EnclaveOutput output;
    ASYLO_EXPECT_OK(server_enclave_->EnterAndRun(input, &output));
    EXPECT_TRUE(output.HasExtension(server_output_config));
    server_address_ =
        absl::StrCat(output.GetExtension(server_output_config).host(), ":",
                     output.GetExtension(server_output_config).port());
  }

  void TearDown() override {
    EnclaveFinal enclave_final;
    ASYLO_EXPECT_OK(manager_->DestroyEnclave(client_enclave_, enclave_final,
                                             /*skip_finalize=*/false));
    ASYLO_EXPECT_OK(manager_->DestroyEnclave(server_enclave_, enclave_final,
                                             /*skip_finalize=*/false));
  }

  ClientEnclaveInput CreateClientInput() {
    ClientEnclaveInput client_input;
    client_input.add_self_grpc_creds_options(
        SGX_LOCAL_GRPC_CREDENTIALS_OPTIONS);
    client_input.add_peer_grpc_creds_options(
        SGX_LOCAL_GRPC_CREDENTIALS_OPTIONS);
    client_input.set_server_address(server_address_);
    client_input.set_rpc_input(kClientInput);
    client_input.set_connection_deadline_milliseconds(1000);
    return client_input;
  }

  StatusOr<SgxIdentityExpectation> CreateSgxIdentityExpectation() {
    SgxIdentity sgx_identity;
    sgx::CodeIdentity *code_identity = sgx_identity.mutable_code_identity();
    code_identity->set_miscselect(0);
    sgx::SecsAttributeSet attributes;
    ASYLO_ASSIGN_OR_RETURN(attributes, sgx::SecsAttributeSet::FromBits(
                                           {sgx::AttributeBit::INIT,
                                            sgx::AttributeBit::DEBUG,
                                            sgx::AttributeBit::MODE64BIT}));
    *code_identity->mutable_attributes() = attributes.ToProtoAttributes();

    sgx::SignerAssignedIdentity *signer_assigned_identity =
        code_identity->mutable_signer_assigned_identity();
    if (!google::protobuf::TextFormat::ParseFromString(
            linux_sgx::kDebugKeyMrsignerTextProto,
            signer_assigned_identity->mutable_mrsigner())) {
      return Status(error::GoogleError::INTERNAL, "Error parsing MRSIGNER");
    }
    signer_assigned_identity->set_isvprodid(kExpectedServerIsvprodid);
    signer_assigned_identity->set_isvsvn(kExpectedServerIsvsvn);

    return asylo::CreateSgxIdentityExpectation(
        std::move(sgx_identity), SgxIdentityMatchSpecOptions::DEFAULT);
  }

  static asylo::EnclaveManager *manager_;
  asylo::EnclaveClient *client_enclave_;
  asylo::EnclaveClient *server_enclave_;
  std::string server_address_;
};

EnclaveManager *ClientSideAuthorizationTest::manager_ = nullptr;

TEST_F(ClientSideAuthorizationTest, AuthorizationSuccess) {
  EnclaveInput input;
  EnclaveOutput output;

  ClientEnclaveInput client_input = CreateClientInput();
  SgxIdentityExpectation sgx_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(sgx_expectation, CreateSgxIdentityExpectation());

  IdentityAclPredicate acl;
  ASYLO_ASSERT_OK_AND_ASSIGN(*acl.mutable_expectation(),
                             SerializeSgxIdentityExpectation(sgx_expectation));

  *client_input.mutable_peer_acl() = std::move(acl);

  *input.MutableExtension(client_enclave_input) = std::move(client_input);

  ASYLO_EXPECT_OK(client_enclave_->EnterAndRun(input, &output));
  EXPECT_EQ(output.GetExtension(rpc_result),
            test::MessengerServer1::ResponseString(kClientInput));
}

TEST_F(ClientSideAuthorizationTest, AuthorizationIncorrectSgxIdentityFailure) {
  EnclaveInput input;
  EnclaveOutput output;

  ClientEnclaveInput client_input = CreateClientInput();
  SgxIdentityExpectation sgx_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(sgx_expectation, CreateSgxIdentityExpectation());
  sgx_expectation.mutable_reference_identity()
      ->mutable_code_identity()
      ->mutable_signer_assigned_identity()
      ->mutable_mrsigner()
      ->mutable_hash()
      ->back() ^= 1;

  IdentityAclPredicate acl;
  ASYLO_ASSERT_OK_AND_ASSIGN(*acl.mutable_expectation(),
                             SerializeSgxIdentityExpectation(sgx_expectation));

  *client_input.mutable_peer_acl() = std::move(acl);

  *input.MutableExtension(client_enclave_input) = std::move(client_input);

  EXPECT_THAT(client_enclave_->EnterAndRun(input, &output),
              StatusIs(error::GoogleError::INTERNAL));
}

}  // namespace
}  // namespace asylo
