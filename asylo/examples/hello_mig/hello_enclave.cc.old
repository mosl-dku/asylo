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

#include "absl/strings/str_cat.h"
#include "asylo/examples/hello_mig/hello.pb.h"
#include "asylo/util/logging.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

int global_visitor_count;

class HelloApplication : public asylo::TrustedApplication {
 public:
  HelloApplication() : visitor_count_(0) {}

  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {
    if (!input.HasExtension(hello_world::enclave_input_hello)) {
      return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                           "Expected a HelloInput extension on input.");
    }
    std::string visitor =
        input.GetExtension(hello_world::enclave_input_hello).to_greet();

	for (int i = 0 ; visitor_count_ < 200 ; i++) {
		LOG(INFO) << "Hello ("<< getpid() << ") #" << visitor_count_++
			<< " \t## " << global_visitor_count++;
		sleep(3);
	}

    if (output) {
      LOG(INFO) << "Incrementing visitor count...";
      output->MutableExtension(hello_world::enclave_output_hello)
          ->set_greeting_message(
              absl::StrCat("Hello ", visitor, "! visitor count #",
                           visitor_count_, " to this enclave."));
    }
    return asylo::Status::OkStatus();
  }

 private:
  uint64_t visitor_count_;
};

namespace asylo {

TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo
