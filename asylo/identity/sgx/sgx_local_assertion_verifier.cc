/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/identity/sgx/sgx_local_assertion_verifier.h"

#include <cstdint>
#include <string>
#include <vector>

#include "absl/synchronization/mutex.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/local_assertion.pb.h"
#include "asylo/identity/sgx/sgx_identity_util_internal.h"
#include "asylo/identity/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/util/status_macros.h"

namespace asylo {

const char *const SgxLocalAssertionVerifier::authority_type_ =
    sgx::kSgxLocalAssertionAuthority;

SgxLocalAssertionVerifier::SgxLocalAssertionVerifier() : initialized_(false) {}

Status SgxLocalAssertionVerifier::Initialize(const std::string &config) {
  if (IsInitialized()) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Already initialized");
  }

  SgxLocalAssertionAuthorityConfig authority_config;
  if (!authority_config.ParseFromString(config)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse input config");
  }

  if (!authority_config.has_attestation_domain()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Config is missing attestation domain");
  }

  attestation_domain_ = authority_config.attestation_domain();

  absl::MutexLock lock(&initialized_mu_);
  initialized_ = true;

  return Status::OkStatus();
}

bool SgxLocalAssertionVerifier::IsInitialized() const {
  absl::MutexLock lock(&initialized_mu_);
  return initialized_;
}

EnclaveIdentityType SgxLocalAssertionVerifier::IdentityType() const {
  return identity_type_;
}

std::string SgxLocalAssertionVerifier::AuthorityType() const {
  return authority_type_;
}

Status SgxLocalAssertionVerifier::CreateAssertionRequest(
    AssertionRequest *request) const {
  if (!IsInitialized()) {
    return Status(error::GoogleError::FAILED_PRECONDITION, "Not initialized");
  }

  request->mutable_description()->set_identity_type(IdentityType());
  request->mutable_description()->set_authority_type(AuthorityType());

  sgx::LocalAssertionRequestAdditionalInfo additional_info;
  additional_info.set_local_attestation_domain(attestation_domain_);

  // The request contains a dump of the raw TARGETINFO structure, which
  // specifies the verifier as the target for the requested assertion. Note that
  // since the layout and endianness of the TARGETINFO structure is defined by
  // the Intel SGX architecture, it is safe to exchange the raw bytes of the
  // structure. An SGX enclave that receives the request can reconstruct the
  // original structure directly from the byte field in the AssertionRequest
  // proto.
  sgx::Targetinfo targetinfo;
  sgx::SetTargetinfoFromSelfIdentity(&targetinfo);
  additional_info.set_targetinfo(
      ConvertTrivialObjectToBinaryString(targetinfo));

  if (!additional_info.SerializeToString(
          request->mutable_additional_information())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to serialize LocalAssertionRequestAdditionalInfo");
  }

  return Status::OkStatus();
}

StatusOr<bool> SgxLocalAssertionVerifier::CanVerify(
    const AssertionOffer &offer) const {
  if (!IsInitialized()) {
    return Status(error::GoogleError::FAILED_PRECONDITION, "Not initialized");
  }

  if (!IsCompatibleAssertionDescription(offer.description())) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "AssertionOffer has incompatible assertion description");
  }

  sgx::LocalAssertionOfferAdditionalInfo additional_info;
  if (!additional_info.ParseFromString(offer.additional_information())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to parse offer additional information");
  }

  return additional_info.local_attestation_domain() == attestation_domain_;
}

Status SgxLocalAssertionVerifier::Verify(const std::string &user_data,
                                         const Assertion &assertion,
                                         EnclaveIdentity *peer_identity) const {
  if (!IsInitialized()) {
    return Status(error::GoogleError::FAILED_PRECONDITION, "Not initialized");
  }

  if (!IsCompatibleAssertionDescription(assertion.description())) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Assertion has incompatible assertion description");
  }

  sgx::LocalAssertion local_assertion;
  if (!local_assertion.ParseFromString(assertion.assertion())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to parse LocalAssertion");
  }

  // First, verify the hardware REPORT embedded in the assertion. This will only
  // succeed if the REPORT is targeted at this enclave. Note that since the
  // layout and endianness of the REPORT structure is defined by the Intel SGX
  // architecture, two SGX enclaves can exchange a REPORT by simply dumping the
  // raw bytes of a REPORT structure into a proto. This code assumes that the
  // assertion originates from a machine that supports the Intel SGX
  // architecture and was copied into the assertion byte-for-byte, so is safe to
  // restore the REPORT structure directly from the deserialized LocalAssertion.
  sgx::Report report;
  ASYLO_RETURN_IF_ERROR(SetTrivialObjectFromBinaryString<sgx::Report>(
      local_assertion.report(), &report));
  ASYLO_RETURN_IF_ERROR(sgx::VerifyHardwareReport(report));

  // Next, verify that the REPORT is cryptographically-bound to the provided
  // |user_data|. This is done by re-constructing the expected REPORTDATA (a
  // SHA256 hash of |user_data| padded with zeros), and comparing it to the
  // actual REPORTDATA inside the REPORT.
  Sha256Hash hash;
  hash.Update(user_data);
  sgx::Reportdata expected_reportdata;
  expected_reportdata.data =
      TrivialZeroObject<UnsafeBytes<sgx::kReportdataSize>>();
  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(hash.CumulativeHash(&digest));
  expected_reportdata.data.replace(/*pos=*/0, digest);

  if (expected_reportdata.data != report.body.reportdata.data) {
    return Status(error::GoogleError::INTERNAL,
                  "Assertion is not bound to the provided user-data");
  }

  // Serialize the protobuf representation of the peer's SGX identity and save
  // it in |peer_identity|.
  SgxIdentity sgx_identity = sgx::ParseSgxIdentityFromHardwareReport(report);
  ASYLO_RETURN_IF_ERROR(sgx::SerializeSgxIdentity(sgx_identity, peer_identity));

  return Status::OkStatus();
}

// Static registration of the LocalAssertionVerifier library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionVerifierMap,
                                     SgxLocalAssertionVerifier);

}  // namespace asylo
