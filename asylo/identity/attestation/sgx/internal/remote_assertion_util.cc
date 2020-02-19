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

#include "asylo/identity/attestation/sgx/internal/remote_assertion_util.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/util/message_differencer.h>
#include "absl/container/flat_hash_set.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/identity_acl_evaluator.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/sgx/pck_certificate_util.h"
#include "asylo/identity/sgx/sgx_identity_expectation_matcher.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

constexpr char kRemoteAssertionVersion[] = "Asylo SGX Remote Assertion v1";

constexpr int kIntelCertChainMinimumLength = 3;
constexpr int kAttestationKeyCertificateIndex = 0;
constexpr int kPckCertificateIndex = 1;

StatusOr<std::unique_ptr<VerifyingKey>> CreateVerifyingKey(
    const AsymmetricSigningKeyProto &key_proto) {
  switch (key_proto.signature_scheme()) {
    case ECDSA_P256_SHA256:
      return EcdsaP256Sha256VerifyingKey::CreateFromProto(key_proto);
    case UNKNOWN_SIGNATURE_SCHEME:
      return Status(
          error::GoogleError::UNIMPLEMENTED,
          absl::StrFormat("Asymmetric key signature scheme (%s) unsupported",
                          SignatureScheme_Name(key_proto.signature_scheme())));
  }
  return Status(
      error::GoogleError::UNIMPLEMENTED,
      absl::StrFormat("Asymmetric key signature scheme (%d) unsupported",
                      key_proto.signature_scheme()));
}

StatusOr<CertificateInterfaceVector>
VerifyCertificateChainsAndExtractIntelCertificateChain(
    const google::protobuf::RepeatedPtrField<CertificateChain> &certificate_chains,
    const CertificateInterface &intel_root,
    CertificateInterfaceSpan additional_root_certificates,
    absl::string_view verifying_key_der) {
  CertificateInterfaceVector intel_cert_chain;
  CertificateFactoryMap factory_map;
  factory_map.emplace(Certificate::X509_DER, X509Certificate::Create);
  factory_map.emplace(Certificate::X509_PEM, X509Certificate::Create);
  factory_map.emplace(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE,
                      AttestationKeyCertificateImpl::Create);

  std::vector<std::unique_ptr<CertificateInterface>> verified_root_certificates;
  VerificationConfig config(/*all_fields=*/true);
  for (const CertificateChain &certificate_chain : certificate_chains) {
    CertificateInterfaceVector certificate_vector;
    ASYLO_ASSIGN_OR_RETURN(
        certificate_vector,
        CreateCertificateChain(factory_map, certificate_chain));

    std::string cert_chain_end_user_key_der;
    ASYLO_ASSIGN_OR_RETURN(cert_chain_end_user_key_der,
                           certificate_vector[0]->SubjectKeyDer());
    if (cert_chain_end_user_key_der != verifying_key_der) {
      continue;
    }
    Status verified =
        VerifyCertificateChain(absl::MakeConstSpan(certificate_vector), config);
    if (!verified.ok()) {
      return verified.WithPrependedContext(absl::StrCat(
          "Failed to verify certificate chain with root cert ",
          certificate_chain.certificates().rbegin()->ShortDebugString()));
    }

    if (*certificate_vector.back() == intel_root) {
      intel_cert_chain = std::move(certificate_vector);
    } else {
      verified_root_certificates.emplace_back(
          certificate_vector.rbegin()->release());
    }
  }

  if (intel_cert_chain.empty()) {
    return Status(error::GoogleError::UNAUTHENTICATED,
                  "Intel certificate chain not found");
  }

  // For each of the required root certificates, verify that there is a valid
  // certificate chain with that root certificate.
  for (const std::unique_ptr<CertificateInterface> &required_root_certificate :
       additional_root_certificates) {
    if (!std::any_of(verified_root_certificates.begin(),
                     verified_root_certificates.end(),
                     [&required_root_certificate](
                         const std::unique_ptr<CertificateInterface> &other) {
                       return *required_root_certificate == *other;
                     })) {
      std::string subject_key;
      ASYLO_ASSIGN_OR_RETURN(subject_key,
                             required_root_certificate->SubjectKeyDer());
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    absl::StrCat("Remote attestation missing certificate chain "
                                 "for root certificate with subject key: ",
                                 absl::BytesToHexString(subject_key)));
    }
  }

  return std::move(intel_cert_chain);
}

Status VerifyAgeExpectation(const IdentityAclPredicate &age_expectation,
                            const CertificateInterface *attestation_key_cert) {
  // Verify that the Intel certificate chain asserts the expected AGE identity.
  AttestationKeyCertificateImpl const *ak_cert =
      dynamic_cast<AttestationKeyCertificateImpl const *>(attestation_key_cert);
  if (ak_cert == nullptr) {
    return Status(error::GoogleError::UNAUTHENTICATED,
                  "Attestation key certificate not provided as part of the "
                  "Intel certificate chain");
  }
  EnclaveIdentity age_identity;
  ASYLO_ASSIGN_OR_RETURN(
      age_identity, SerializeSgxIdentity(ak_cert->GetAssertedSgxIdentity()));
  std::string explanation;
  SgxIdentityExpectationMatcher matcher;
  StatusOr<bool> age_match_result = EvaluateIdentityAcl(
      {age_identity}, age_expectation, matcher, &explanation);
  if (!age_match_result.ok()) {
    return age_match_result.status().WithPrependedContext(
        "Error evaluating AGE identity expectation");
  }
  if (!age_match_result.ValueOrDie()) {
    return Status(
        error::GoogleError::UNAUTHENTICATED,
        absl::StrCat("AGE identity did not match expectation: ", explanation));
  }
  return Status::OkStatus();
}

StatusOr<SgxExtensions> ExtractSgxExtensions(
    absl::Span<X509Extension> pck_extensions) {
  for (const X509Extension &extension : pck_extensions) {
    if (extension.oid == GetSgxExtensionsOid()) {
      return ReadSgxExtensions(extension.value);
    }
  }
  return Status(error::GoogleError::INVALID_ARGUMENT,
                "PCK certificate does not contain SGX extensions");
}

StatusOr<MachineConfiguration> ExtractMachineConfiguration(
    const CertificateInterface *pck_certificate) {
  X509Certificate const *pck_cert =
      dynamic_cast<X509Certificate const *>(pck_certificate);
  if (pck_cert == nullptr) {
    return Status(error::GoogleError::UNAUTHENTICATED,
                  "PCK certificate is not an X.509 certificate");
  }

  auto pck_extensions_result = pck_cert->GetOtherExtensions();
  if (!pck_extensions_result.ok()) {
    return pck_extensions_result.status().WithPrependedContext(
        "PCK certificate does not contain extensions");
  }
  std::vector<X509Extension> pck_extensions =
      std::move(pck_extensions_result).ValueOrDie();
  SgxExtensions sgx_extensions;
  ASYLO_ASSIGN_OR_RETURN(sgx_extensions,
                         ExtractSgxExtensions(absl::MakeSpan(pck_extensions)));

  sgx::MachineConfiguration machine_config;

  *machine_config.mutable_cpu_svn() = std::move(sgx_extensions.cpu_svn);
  machine_config.set_sgx_type(sgx_extensions.sgx_type);

  return machine_config;
}

}  // namespace

Status MakeRemoteAssertion(const std::string &user_data,
                           const SgxIdentity &identity,
                           const SigningKey &signing_key,
                           const std::vector<CertificateChain> &cert_chains,
                           RemoteAssertion *assertion) {
  assertion->Clear();
  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSIGN_OR_RETURN(verifying_key, signing_key.GetVerifyingKey());
  ASYLO_ASSIGN_OR_RETURN(
      *assertion->mutable_verifying_key(),
      verifying_key->SerializeToKeyProto(ASYMMETRIC_KEY_DER));

  for (const auto &chain : cert_chains) {
    *assertion->add_certificate_chains() = chain;
  }

  RemoteAssertionPayload payload;
  payload.set_version(kRemoteAssertionVersion);
  payload.set_signature_scheme(signing_key.GetSignatureScheme());
  payload.set_user_data(user_data);
  *payload.mutable_identity() = identity;

  if (!payload.SerializeToString(assertion->mutable_payload())) {
    return Status(error::GoogleError::INTERNAL, "Serialization failed");
  }

  std::vector<uint8_t> signature;
  ASYLO_RETURN_IF_ERROR(signing_key.Sign(assertion->payload(), &signature));
  assertion->set_signature(CopyToByteContainer<std::string>(signature));
  return Status::OkStatus();
}

Status VerifyRemoteAssertion(
    const std::string &user_data, const RemoteAssertion &assertion,
    const CertificateInterface &intel_root,
    CertificateInterfaceSpan additional_root_certificates,
    const IdentityAclPredicate &age_identity_expectation,
    SgxIdentity *identity) {
  // Verify that the user data matches the user data in the payload.
  RemoteAssertionPayload payload;
  if (!payload.ParseFromString(assertion.payload())) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse payload");
  }
  if (payload.user_data() != user_data) {
    return Status(error::GoogleError::UNAUTHENTICATED,
                  "User data in payload does not match |user_data|");
  }

  const AsymmetricSigningKeyProto &verifying_key_proto =
      assertion.verifying_key();

  // Verify that the signature scheme in the payload matches the signature
  // scheme in the remote assertion.
  if (payload.signature_scheme() != verifying_key_proto.signature_scheme()) {
    return Status(
        error::GoogleError::UNAUTHENTICATED,
        absl::StrFormat(
            "Signature scheme in assertion (%s) does not match signature "
            "scheme in payload (%s)",
            SignatureScheme_Name(verifying_key_proto.signature_scheme()),
            SignatureScheme_Name(payload.signature_scheme())));
  }

  // Verify the remote assertion signature with the public key.
  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSIGN_OR_RETURN(verifying_key,
                         CreateVerifyingKey(verifying_key_proto));
  std::string verifying_key_der;
  ASYLO_ASSIGN_OR_RETURN(verifying_key_der, verifying_key->SerializeToDer());
  ASYLO_RETURN_IF_ERROR(
      verifying_key->Verify(assertion.payload(), assertion.signature()));

  CertificateInterfaceVector intel_cert_chain;
  ASYLO_ASSIGN_OR_RETURN(intel_cert_chain,
                         VerifyCertificateChainsAndExtractIntelCertificateChain(
                             assertion.certificate_chains(), intel_root,
                             additional_root_certificates, verifying_key_der));
  if (intel_cert_chain.size() < kIntelCertChainMinimumLength) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrFormat("Length of Intel certificate chain (%d) is shorter "
                        "than the minimum length (%d)",
                        intel_cert_chain.size(), kIntelCertChainMinimumLength));
  }

  ASYLO_RETURN_IF_ERROR(VerifyAgeExpectation(
      age_identity_expectation,
      intel_cert_chain[kAttestationKeyCertificateIndex].get()));

  // Extract the code identity.
  *identity = payload.identity();
  ASYLO_ASSIGN_OR_RETURN(*identity->mutable_machine_configuration(),
                         ExtractMachineConfiguration(
                             intel_cert_chain[kPckCertificateIndex].get()));

  return Status::OkStatus();
}

}  // namespace sgx
}  // namespace asylo
