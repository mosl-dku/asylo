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
			out_length
		output param for key length
	output: keybytes
	N.B: the caller should free the keybytes
*/
uint8_t *ReadEncKey(const char *key_file, int *out_length)
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
	*out_length = nrbytes;
	return p;
}

/*
	Decrypt Data encryption key
		from the encrypted_key (enc_key) and certificate (key-decryption-key)
	input:  byte[] enc_key
				encrypted key from file,
			int enc_key_len
				key length of enc_key
			RSA* Kpub
				key-decryption-key from certificate
	output: byte[] dek
				data encryption key
				the caller should free the dek
*/
uint8_t *DecryptDEK(uint8_t *enc_key, int klen, RSA *Kpub)
{
	uint8_t str_key[256];
	int key_length;
	int kdk_length = 32;
	uint8_t *kdk;
	memset(str_key, 0, 256);
	key_length = RSA_public_decrypt(klen, enc_key, str_key, Kpub, RSA_PKCS1_PADDING);
	std::string input_key((char *)str_key);

	if (key_length <= 0) {
		LOG(ERROR) << "DecryptDEK failed";
		return NULL;
	}
	LOG(INFO) << "[AES-GCM key]: "<< input_key << "\nkeylen: " << key_length;

	kdk = RetriveKeyFromString(ReplaceAll(input_key, std::string(" "), std::string("")), kdk_length);
	return kdk;
}

/*
	Decrypt And Decompress
		The plaindata is compressed and then encrypted
	input: 	std::string cipher_text
				the ciphertext (original data)
			uint8_t* key
				the ciphering key
*/
std::string DecryptAndDecompress(std::string &cipher_text, uint8_t *key)
{
	int data_len = cipher_text.length();
	size_t out_len;
	uint8_t* dout = new uint8_t[data_len];
	uint8_t nonce[32] = {0,};

	EVP_AEAD_CTX ctx;
    const EVP_AEAD *const aead = EVP_aead_aes_256_gcm();
    size_t nonce_len= EVP_AEAD_nonce_length(aead);
    EVP_AEAD_CTX_init(&ctx, aead, key, EVP_AEAD_key_length(aead),EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
    EVP_AEAD_CTX_open(&ctx, dout, &out_len, data_len, nonce, nonce_len, (const uint8_t *)(cipher_text.c_str()), data_len,NULL, 0);
	if (out_len == 0) {
		return std::string();
	}
    //LOG(INFO) << "[DEBUG] Decrypted Data ("<< out_len <<"): "<< dout;

    // decompress
    unsigned char* pCompressedData = (unsigned char*) dout;
    unsigned long out_buffer_length = (out_len << 4);
    unsigned char * pUncompressedData = new unsigned char [out_buffer_length];
    if (pCompressedData != nullptr) memset(pUncompressedData,0,out_buffer_length);
    int nResult = uncompress(pUncompressedData, &out_buffer_length, dout, out_len);
    if(nResult != Z_OK) {
		return std::string();
	}
    //LOG(INFO) << "[DEBUG] Decrypted and Uncompressed Data ("<< out_buffer_length <<"): " << pUncompressedData;

	std::string out((char *)pUncompressedData);
	return out;
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
	int enc_key_len;

	// Confirm that |*request| has an |ciphertext| field.
	if (!request->has_ciphertext()) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
			"No input ciphertext given");
	}
	// Confirm that |*request| has an |ciphertext| field.
	if (!request->has_key_filename()) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
			"No input key_filename given");
	}



	char certificate_file[] = "/key_material/public.crt";
	char *encrypted_key_filename = (char *)request->key_filename().c_str();
	// Check the enc_key file: encrypted key
	pubkey = GetKDK(certificate_file);
	if (pubkey == NULL) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
								"No valid certificate file available");
	}
	enc_key = ReadEncKey(encrypted_key_filename, &enc_key_len);
	if (enc_key == NULL) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
								"No valid key file available");
	}

	dek = DecryptDEK(enc_key, enc_key_len, pubkey);
	if (dek == NULL) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
								"decryption key derivation failed");
	}

	std::string cipher_text = request->ciphertext();
	std::string plaintext = DecryptAndDecompress(cipher_text, dek);
	if (plaintext.empty()) {
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "Decryption failed");
	}

	// Return the plaintext.
	response->set_plaintext(plaintext);
	return ::grpc::Status::OK;
}

}  // namespace decryptor_server
}  // namespace examples
