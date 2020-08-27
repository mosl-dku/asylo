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

#include "asylo/examples/hello_world/hello.pb.h"
#include "asylo/util/logging.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status_macros.h"
#include "asylo/crypto/aead_key.h"
#include "zlib.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"


const char AssociatedDataBuf[] = "";
const size_t KeySize =32;
unsigned char chiper[256], plain[256];

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

class HelloApplication : public asylo::TrustedApplication {
 public:
  HelloApplication() : visitor_count_(0) {}

  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {
    if (!input.HasExtension(hello_world::enclave_input_hello)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a HelloInput extension on input.");
    }
    std::string dummy =
        input.GetExtension(hello_world::enclave_input_hello).to_greet();

    RSA *pPubKey = RetrivePubKeyFromX509("/home/yeo/data/public.crt");
    ReadFromFS("/home/yeo/data/enc_key", chiper);
    int plain_len = RSA_public_decrypt(sizeof(chiper), chiper, plain, pPubKey, RSA_PKCS1_PADDING);
    std::string input_key((char*)plain);
    
    /*
    input_key = "f2 fc e5 0d c7 91 9c d6 07 7e 60 35 3e c9 ab d5 a0 a8 4a 2d 7d a5 07 e8 34 a7 e0 c0 6d ea bc 20";
    */
    /*std::string file_path =
        input.GetExtensio(hello_world::enclave_input_hello).file();
    */

    std::string file_path = "/home/yeo/data/enc_data";
    LOG(INFO) << "[DEBUG] AES-GCM KEY :" << input_key;
    input_key = ReplaceAll(input_key,std::string(" "),std::string(""));
    uint8_t* key = RetriveKeyFromString(ReplaceAll(input_key,std::string(" "),std::string("")),KeySize);

    int fd = open(file_path.c_str(), O_RDWR);
    uint8_t fin[1024];
    size_t fin_len = read(fd,&fin,1024);
    uint8_t nonce[32] ={0,};

    uint8_t dout[1024];
    size_t dout_len = 0;
    EVP_AEAD_CTX ctx;
    const EVP_AEAD *const aead = EVP_aead_aes_256_gcm();
    size_t nonce_len= EVP_AEAD_nonce_length(aead);
    EVP_AEAD_CTX_init(&ctx, aead, key, EVP_AEAD_key_length(aead),EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
    EVP_AEAD_CTX_open(&ctx, dout,&dout_len,1024, nonce, nonce_len, fin, fin_len,NULL, 0);
    LOG(INFO) << "[DEBUG] Decrypted Data : "<< dout;

    unsigned char* pCompressedData = (unsigned char*) dout;

	// decompress
	  unsigned long nDataSize = 2048;
	  unsigned char * pUncompressedData = new unsigned char [nDataSize];
    if(pCompressedData !=nullptr)
    memset(pUncompressedData,0,2048);
    int nResult = uncompress(pUncompressedData, &nDataSize, dout, dout_len);
    if(nResult != Z_OK)
    {};
    LOG(INFO) << "[DEBUG] Decrypted and Uncompressed Data : " << pUncompressedData;


    if (output) {
      output->MutableExtension(hello_world::enclave_output_hello)
          ->set_greeting_message("Done");
    }
    return asylo::Status::OkStatus();
  }

 private:
  uint64_t visitor_count_;
};

namespace asylo {

TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo
