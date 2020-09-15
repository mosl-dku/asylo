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
#include <cstdint>

#include <atomic>
#include <cstddef>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/types.h>
#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "asylo/examples/decryptor_server/decryptor_server_impl.h"

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "include/grpcpp/grpcpp.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status_macros.h"
#include "asylo/crypto/aead_key.h"
#include "zlib.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"


namespace examples {
namespace decryptor_server {


const char AssociatedDataBuf[] = "";
const size_t KeySize =32;
unsigned char cipher[256], plain[256];

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
        size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != std::string::npos) {
                str.replace(start_pos, from.length(), to);
                start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
        }
        return str;
}


uint8_t* RetriveKeyFromString(std::string stf,size_t key_size){
        uint8_t *key=new uint8_t[key_size];
        unsigned long ul;
        char *dummy;

        for(int i=0; i<key_size; ){
                ul = strtoul(stf.substr( i*2, 8).c_str(), &dummy, 16);
                key[i++] = (ul & 0xff000000)>>24;
                key[i++] = (ul & 0xff0000)>>16;
                key[i++] = (ul & 0xff00)>>8;
                key[i++] = (ul & 0xff);
        }

        return key;
}

RSA *RetrivePubKeyFromX509(const char *file_name)
{
        BIO *certbio = BIO_new(BIO_s_file());
        BIO_read_filename(certbio, file_name);
        RSA *output = EVP_PKEY_get0_RSA(
                        X509_get_pubkey(
                                PEM_read_bio_X509(certbio, NULL, 0, NULL)));
        BIO_free(certbio);
        return output;
}

int ReadFromFS(const char *file_name, unsigned char *p)
{
        BIO *inputbio = BIO_new(BIO_s_file());
        BIO_read_filename(inputbio, file_name);
        int nrbytes = BIO_read(inputbio, p, 256);
        return nrbytes;
}

DecryptorServerImpl::DecryptorServerImpl()
    : Service()
{}

::grpc::Status DecryptorServerImpl::GetDecryption(
    ::grpc::ServerContext *context, const GetDecryptionRequest *request,
    GetDecryptionResponse *response) {
	// To decrypt data, 
	/*
		1. extract the key decryption key from certificate
		2. read encrypted key file
		3. decrypt the data encryption key (2) with the key decryption key (1)
		4. read the encrypted data (ciphertext in the request)
		5. decrypt data (4) with the key decryption key (3)
	*/
	// Check the enc_key file: encrypted key

  // Confirm that |*request| has an |ciphertext| field.
  if (!request->has_ciphertext()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "No input word given");
  }


  // Return the plaintext.
  response->set_plaintext(request->ciphertext());
  return ::grpc::Status::OK;
}

}  // namespace decryptor_server
}  // namespace examples
