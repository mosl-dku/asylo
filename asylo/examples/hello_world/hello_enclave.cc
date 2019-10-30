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

#include <sys/wait.h>
#include <unistd.h>
#include <cstdint>

extern "C" {
pid_t enclave_fork();
}

#include "absl/strings/str_cat.h"
#include "asylo/examples/hello_world/hello.pb.h"
#include "asylo/util/logging.h"
#include "asylo/trusted_application.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status.h"
#include "asylo/platform/primitives/trusted_runtime.h"

using namespace asylo;

class HelloApplication : public asylo::TrustedApplication {
/*
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

    LOG(INFO) << "Hello " << visitor;
		  output->MutableExtension(hello_world::enclave_output_hello)
			  ->set_greeting_message("");
	
    pid_t pid = enclave_fork();

    if (pid < 0) {
      abort();
    }   
    if (pid == 0) {
      // Child enclave.
		if (output) {
		  LOG(INFO) << "Incrementing visitor count...";
		  output->MutableExtension(hello_world::enclave_output_hello)
			  ->set_greeting_message(
				  absl::StrCat("Hello ", visitor, "(",getpid(),")! You are visitor #",
							   ++visitor_count_, " to this enclave."));
		}

    } else {
      // Parent enclave.
      // Wait for the child enclave exits, and checks whether it exited
      // normally.
      int status;
      if (wait(&status) == -1) {
        return Status(static_cast<error::PosixError>(errno),
                      absl::StrCat("Error waiting for child: ",
                                   strerror(errno)));
      }
		if (output) {
		  LOG(INFO) << "Incrementing visitor count...";
		  output->MutableExtension(hello_world::enclave_output_hello)
			  ->set_greeting_message(
				  absl::StrCat("Hello ", visitor, "! You are visitor #",
							   ++visitor_count_, " to this enclave."));
		}

      if (!WIFEXITED(status)) {
        //return Status(error::GoogleError::INTERNAL, "child enclave aborted");
      }

    }
    return asylo::Status::OkStatus();
  }

 private:
  uint64_t visitor_count_;
*/

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
			LOG(INFO) << "Hello " << visitor;
			for(unsigned int i=0; i<0xffffffff;i++);
			for(unsigned int i=0; i<0xffffffff;i++);
			for(unsigned int i=0; i<0xffffffff;i++);
			for(unsigned int i=0; i<0xffffffff;i++);
			for(unsigned int i=0; i<0xffffffff;i++);
			for(unsigned int i=0; i<0xffffffff;i++);
			for(unsigned int i=0; i<0xffffffff;i++);
			for(unsigned int i=0; i<0xffffffff;i++);
			if (output) {
				LOG(INFO) << "Incrementing visitor count...";
				output->MutableExtension(hello_world::enclave_output_hello)
					->set_greeting_message(
							absl::StrCat("Hello ", visitor, "! You are visitor #",
								++visitor_count_, " to this enclave."));
			}
			return asylo::Status::OkStatus();
		}

	private:
		uint64_t visitor_count_;
};

namespace asylo {

TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo
