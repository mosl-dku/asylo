/*
 *
 * Copyright 2020 Asylo authors
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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/asymmetric_encryption_key.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/rsa_oaep_encryption_key.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/internal/ppid_ek.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client_impl.h"
#include "asylo/util/http_fetcher_impl.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/proto_flag.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace {

constexpr uint32_t kPceId = 0;
constexpr int kInvalidPceSvn = -1;

}  // namespace

ABSL_FLAG(
    std::string, api_key, "",
    "(required) API key to authenticate to the Intel PCS. Get an API key by "
    "registering with Intel at "
    "https://api.portal.trustedservices.intel.com/provisioning-certification.");
ABSL_FLAG(
    std::string, ppid, "",
    "(required) The per-processor identifier, expressed as ASCII hexadeximal.");

ABSL_FLAG(std::string, cpu_svn, "",
          "(required) The CPU's secure version number, expressed as ASCII "
          "hexadecimal.");
ABSL_FLAG(int, pce_svn, kInvalidPceSvn,
          "(required) The PCE's secure version number.");
ABSL_FLAG(std::string, outfile, "certs.out",
          "The name of the file where the CertificateChain will be written.");
ABSL_FLAG(std::string, outfmt, "textproto",
          "The output format to use. Valid options are 'textproto' or 'pem'. "
          "Defaults to textproto.");

namespace {

using ::asylo::sgx::CpuSvn;
using ::asylo::sgx::kPpidEkTextProto;
using ::asylo::sgx::PceId;
using ::asylo::sgx::PceSvn;
using ::asylo::sgx::Ppid;
using ::asylo::sgx::SgxPcsClientImpl;
using ::asylo::sgx::ValidateCpuSvn;
using ::asylo::sgx::ValidatePceSvn;
using ::asylo::sgx::ValidatePpid;

// This certificate was pulled from the Chrome browser root certificate store.
constexpr char kCaCert[] =
    R"cert(-----BEGIN CERTIFICATE-----
MIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMTE5
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCR
6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2fcHK3YX/JSw8X
pz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs/Q36nGz637CC
9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio5JIk2kNrYrhV
/erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62a+pGx8cgoLEf
Zd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7gUYPDCUZObT6Z
+pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlWPc9vqv9JWL7w
qP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArncevPDt09qZah
SL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0AuqLZxUpaVIC
u9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dma/RMhnEw6abf
Fobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5WdYgGq/yapiq
crxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo0IwQDAdBgNVHQ4E
FgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAArx1UaEt65Ru2yyTUEUAJNMnMvl
wFTPoCWOAvn9sKIN9SCYPBMtrFaisNZ+EZLpLrqeLppysb0ZRGxhNaKatBYSaVqM
4dc+pBroLwP0rmEdEBsqpIt6xf4FpuHA1sj+nq6PK7o9mfjYcwlYRm6mnPTXJ9OV
2jeDchzTc+CiR5kDOF3VSXkAKRzH7JsgHAckaVd4sjn8OoSgtZx8jb8uk2Intzna
FxiuvTwJaP+EmzzV1gsD41eeFPfR60/IvYcjt7ZJQ3mFXLrrkguhxuhoqEwWsRqZ
CuhTLJK7oQkYdQxlqHvLI7cawiiFwxv/0Cti76R7CZGYZ4wUAc1oBmpjIXUDgIiK
boHGhfKppC3n9KUkEEeDys30jXlYsQab5xoq2Z0B15R97QNKyvDb6KkBPvVWmcke
jkk9u+UJueBPSZI9FoJAzMxZxuY67RIuaTxslbH9qh17f4a+Hg4yRvv7E491f0yL
S0Zj/gA0QHDBw7mh3aZw4gSzQbzpgJHqZJx64SIDqZxubw5lT2yHh17zbqD5daWb
QOhTsiedSrnAdyGN/4fy3ryM7xfft0kL0fJuMAsaDk527RH89elWsn2/x20Kk4yl
0MC2Hb46TpSi125sC8KKfPog88Tk5c0NqMuRkrF8hey1FGlmDoLnzc7ILaZRfyHB
NVOFBkpdn627G190
-----END CERTIFICATE-----)cert";

// Helper class to create a temp file for holding the root cert. The file is
// removed when CertFile is destroyed.
class CertFile {
 public:
  CertFile() : tempfile_(mkstemp(filename_)) {
    CHECK_NE(tempfile_, -1) << strerror(errno);
    CHECK_NE(write(tempfile_, kCaCert, sizeof(kCaCert) - 1), -1)
        << strerror(errno);
  }

  ~CertFile() {
    close(tempfile_);
    unlink(filename_);
  }

  std::string Path() const { return filename_; }

 private:
  char filename_[16] = "/tmp/certXXXXXX";
  int tempfile_;
};

Ppid GetPpid() {
  std::string ppid_input = absl::GetFlag(FLAGS_ppid);
  Ppid ppid;
  if (ppid_input.empty()) {
    LOG(QFATAL) << "PPID must be specified.";
  } else {
    ppid.set_value(absl::HexStringToBytes(ppid_input));
    ASYLO_CHECK_OK(ValidatePpid(ppid))
        << "Invalid PPID '" << ppid_input << "'.";
  }
  return ppid;
}

CpuSvn GetCpuSvn() {
  std::string cpu_svn_input = absl::GetFlag(FLAGS_cpu_svn);
  CpuSvn cpu_svn;
  if (cpu_svn_input.empty()) {
    LOG(QFATAL) << "CPUSVN must be specified.";
  } else {
    cpu_svn.set_value(absl::HexStringToBytes(cpu_svn_input));
    ASYLO_CHECK_OK(ValidateCpuSvn(cpu_svn))
        << "Invalid CPUSVN'" << cpu_svn_input << "'.";
  }
  return cpu_svn;
}

PceSvn GetPceSvn() {
  int pce_svn_input = absl::GetFlag(FLAGS_pce_svn);
  PceSvn pce_svn;
  if (pce_svn_input == kInvalidPceSvn) {
    LOG(QFATAL) << "PCESVN must be specified.";
  } else {
    pce_svn.set_value(pce_svn_input);
    ASYLO_CHECK_OK(ValidatePceSvn(pce_svn))
        << "Invalid PCESVN: " << pce_svn_input << ".";
  }
  return pce_svn;
}

PceId GetPceId() {
  PceId pce_id;
  pce_id.set_value(kPceId);
  return pce_id;
}

void WritePemCert(const asylo::Certificate &cert_proto, std::ofstream &output) {
  if (cert_proto.format() == asylo::Certificate::X509_PEM) {
    output << cert_proto.data();
    return;
  }

  auto cert_result = asylo::X509Certificate::Create(cert_proto);
  ASYLO_CHECK_OK(cert_result.status());

  auto cert_proto_result = cert_result.ValueOrDie()->ToCertificateProto(
      asylo::Certificate::X509_PEM);
  ASYLO_CHECK_OK(cert_proto_result.status());
  output << cert_proto_result.ValueOrDie().data();
}

void WritePemOutput(asylo::sgx::GetPckCertificateResult cert_result) {
  std::ofstream output(absl::GetFlag(FLAGS_outfile));
  WritePemCert(cert_result.pck_cert, output);
  for (auto &cert : cert_result.issuer_cert_chain.certificates()) {
    WritePemCert(cert, output);
  }
}

void WriteTextProtoOutput(asylo::sgx::GetPckCertificateResult cert_result) {
  asylo::CertificateChain chain;
  *chain.add_certificates() = std::move(cert_result.pck_cert);
  for (auto &cert : cert_result.issuer_cert_chain.certificates()) {
    *chain.add_certificates() = std::move(cert);
  }

  int output_fd = creat(absl::GetFlag(FLAGS_outfile).c_str(), /*mode=*/0664);
  CHECK_NE(output_fd, -1) << strerror(errno);
  google::protobuf::io::FileOutputStream output(output_fd);
  google::protobuf::TextFormat::Print(chain, &output);
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);

  std::string api_key = absl::GetFlag(FLAGS_api_key);
  CHECK(!api_key.empty()) << "The '" << FLAGS_api_key.Name()
                          << "' flag is required.";

  auto ppid_ek = asylo::RsaOaepEncryptionKey::CreateFromProto(
      asylo::ParseTextProtoOrDie(kPpidEkTextProto), asylo::SHA256);
  ASYLO_CHECK_OK(ppid_ek.status()) << "Error creating PPID EK.";

  CertFile cert_file;
  auto fetcher = absl::make_unique<asylo::HttpFetcherImpl>(cert_file.Path());
  auto client_result = SgxPcsClientImpl::Create(
      std::move(fetcher), std::move(ppid_ek).ValueOrDie(), api_key);
  ASYLO_CHECK_OK(client_result.status()) << "Error creating PCS client.";

  auto cert_result = client_result.ValueOrDie()->GetPckCertificate(
      GetPpid(), GetCpuSvn(), GetPceSvn(), GetPceId());
  ASYLO_CHECK_OK(cert_result.status()) << "Error fetching certificate(s).";

  std::string outfmt = absl::GetFlag(FLAGS_outfmt);
  LOG(INFO) << "Writing the certificate chain to "
            << absl::GetFlag(FLAGS_outfile) << ".";
  if (outfmt == "textproto") {
    WriteTextProtoOutput(std::move(cert_result).ValueOrDie());
    return 0;
  } else if (outfmt == "pem") {
    WritePemOutput(std::move(cert_result).ValueOrDie());
    return 0;
  }

  LOG(QFATAL) << "Invalid " << FLAGS_outfmt.Name() << " value: " << outfmt
              << ".";

  return -1;
}
