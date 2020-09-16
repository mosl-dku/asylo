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
#include "asylo/examples/decryptor_server/decryptor_server.grpc.pb.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server.h"

namespace examples {
namespace decryptor_server {

class DecryptorServerImpl final : public Decryptor::Service {
 public:
  // Configure the server.
  explicit DecryptorServerImpl();

 private:
  ::grpc::Status Decrypt(::grpc::ServerContext *context,
                                const GetDecryptionRequest *request,
                                GetDecryptionResponse *response) override;

};

}  // namespace decryptor_server
}  // namespace examples

#endif  // ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_IMPL_H_
