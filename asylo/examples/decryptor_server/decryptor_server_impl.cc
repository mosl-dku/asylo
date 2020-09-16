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

/*
	Retrive Key decryption Key from certificate file
*/
RSA *GetKDK(const char *cert_file)
{
	struct stat sbuf;
    BIO *certbio = NULL;
    RSA *output = NULL;
	int res = stat(cert_file, &sbuf);
	if (res == 0) {
		// works only when the cert_file exists
		certbio = BIO_new(BIO_s_file());
		BIO_read_filename(certbio, cert_file);
		output = EVP_PKEY_get0_RSA(
			X509_get_pubkey(PEM_read_bio_X509(certbio, NULL, 0, NULL)));
		BIO_free(certbio);
	}

	if (output == NULL) {
		LOG(ERROR) << "GetKDK failed";
		return NULL;
	}
	LOG(INFO) << "[GetKDK]: "<< output;
    return output;
}

/*
	Read encrypted key-decryption-key
	input: key_file
		the filename for the encrypted key
	output: keybytes
	N.B: the caller should free the keybytes
*/
uint8_t *ReadEncKey(const char *key_file)
{
	struct stat sbuf;
	uint8_t *p = NULL;
    BIO *inputbio = NULL;
	int nrbytes = 0;
	int res = stat(key_file, &sbuf);
	if (res == 0) {
		// works only when the cert_file exists
		p = new uint8_t[256];
		inputbio = BIO_new(BIO_s_file());
		BIO_read_filename(inputbio, key_file);
		nrbytes = BIO_read(inputbio, p, 256);
	}

	if (nrbytes <= 0) {
		LOG(ERROR) << "ReadEncKey failed";
		return NULL;
	}
	LOG(INFO) << "[enc_key]: "<< p;
	return p;
}

/*
	Decrypt Data encryption key
		from the encrypted_key (enc_key) and certificate (key-decryption-key)
	input:  byte[] enc_key
				encrypted key from file,
			RSA* Kpub
				key-decryption-key from certificate
	output: byte[] dek
				data encryption key
*/
uint8_t *DecryptDEK(uint8_t *enc_key, RSA *Kpub)
{
	uint8_t *kdk = new uint8_t[256];
	int key_length = 0;
	key_length = RSA_public_decrypt(sizeof(enc_key), enc_key, kdk, Kpub, RSA_PKCS1_PADDING);
	std::string input_key((char *)kdk);

	if (key_length == 0) {
		LOG(ERROR) << "DecryptDEK failed";
		return NULL;
	}
	LOG(INFO) << "[AES-GCM key]: "<< input_key;
	return kdk;
}

DecryptorServerImpl::DecryptorServerImpl()
    : Service()
{}

::grpc::Status DecryptorServerImpl::Decrypt(
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
	RSA *pubkey; // key decryption key
	uint8_t *dek; // data encryption key
	uint8_t *enc_key;

	char certificate_file[] = "/home/yeo/data/public.crt";
	char encrypted_key[] = "/home/yeo/data/enc_key";
	// Check the enc_key file: encrypted key
	pubkey = GetKDK(certificate_file);
	if (pubkey == NULL) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
								"No valid certificate file available");
	}
	enc_key = ReadEncKey(encrypted_key);
	if (enc_key == NULL) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
								"No valid key file available");
	}

	dek = DecryptDEK(enc_key, pubkey);
	if (dek == NULL) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
								"decryption key derivation failed");
	}


  // Confirm that |*request| has an |ciphertext| field.
  if (!request->has_ciphertext()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "No input word given");
  }
	std::string cipher_text = request->ciphertext();
	//plaintext = DecryptAndDecompress(cipher_text, dek);


  // Return the plaintext.
  response->set_plaintext(request->ciphertext());
  return ::grpc::Status::OK;
}

}  // namespace decryptor_server
}  // namespace examples
