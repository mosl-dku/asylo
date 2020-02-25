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

#ifndef ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_IMPL_H_
#define ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_IMPL_H_

#include <string>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "asylo/examples/grpc_server/translator_server.grpc.pb.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server.h"

namespace examples {
namespace grpc_server {

class TranslatorServerImpl final : public Translator::Service {
 public:
  // Configure the server.
  explicit TranslatorServerImpl();

 private:
  ::grpc::Status MatMul(::grpc::ServerContext *context,
                              const GetMatMulRequest *query,
                              GetMatmulResponse *response) ;

  ::grpc::Status GetTranslation(::grpc::ServerContext *context,
                                const GetTranslationRequest *request,
                                GetTranslationResponse *response) override;

  // A map from words to their translations.
  absl::flat_hash_map<std::string, std::string> translation_map_;

  void split(const std::string &str, std::vector<std::string> &vect, char ch);
	void getDim(std::string size,int& count_rows, int& count_columns);
	double** getMat(std::string size, std::vector<double> input, int &count_rows, int &count_columns);
	double** transpose(std::vector<double> input, int &count_rows, int &count_columns);
	double** matmul(double** input_mat1, double** input_mat2);
	void getOutput();
 	void setOutput(GetMatmulResponse *response);
	void deleteMemory();
};

}  // namespace grpc_server
}  // namespace examples

#endif  // ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_IMPL_H_
