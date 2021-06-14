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

#include <iostream>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_split.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/util/logging.h"
#include "mig_world/mig.pb.h"
#include "asylo/platform/core/generic_enclave_client.h"

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#define SIGSNAPSHOT	SIGUSR2

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(std::string, names, "",
          "A comma-separated list of names to pass to the enclave");

// some global variables
asylo::primitives::SgxEnclaveClient *client;
void *enc_base;
size_t enc_size;
int g_argc;
char ** g_argv;
asylo::SnapshotLayout layout;
struct sigaction old_sa;
struct sigaction new_sa;
struct sigaction old_mig_sa;
struct sigaction new_mig_sa;

struct timeval tv;
struct timeval tve;

// some functions definitions
void ReloadEnclave(asylo::EnclaveManager *, void *, size_t);
void ResumeExecution(asylo::EnclaveManager *);
void Destroy(asylo::EnclaveManager *);
asylo::EnclaveConfig GetApplicationConfig();

// trapping segfault  == initialize enclave loading at child
void initiate_enclave(int signo)
{
	int wstatus;
	int pid = fork();
	if (pid < 0) {
		LOG(FATAL) << "fork failed";
	}else if (pid == 0) {
		pid = fork();
		if (pid < 0) {
			LOG(FATAL) << "fork failed";
		} else if (pid >0) {
			// wait a second for restarting aesmd service
			//check aesmd service status
			char buff_aesmd[2];
			FILE *fp_aesmd;
			while(1){
				fp_aesmd = popen("/usr/script/aesmd_check.sh", "r");
				if(fp_aesmd == NULL){
					LOG(FATAL) << "popen failed";
					break;
				}
				fgets(buff_aesmd, 2, fp_aesmd);
				fclose(fp_aesmd);
				if(strcmp(buff_aesmd, "1"))
					LOG(INFO) << "waiting aesmd restart...";
				else {
					LOG(INFO) << "aesmd service restarted";
					break;
				}
			}
			usleep(70000);
			asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
			auto manager_result = asylo::EnclaveManager::Instance();
			if (!manager_result.ok()) {
				LOG(QFATAL) << "EnclaveManager unavailable: " << manager_result.status();
			}

			asylo::EnclaveManager *manager = manager_result.ValueOrDie();
			
			// now reload enclave; then restore snapshot from migration
			ReloadEnclave(manager, enc_base, enc_size);
			LOG(INFO) << "Reload finished";
			ResumeExecution(manager);
			Destroy(manager);

			exit(0);
			// never reach here
			return;
		} else {
			//child exec. restart aesmd service
			LOG(INFO) << "aesmd service restarting...\n";
			execl("/usr/bin/sudo", "sudo", "service", "aesmd", "restart", 0);
			exit(0);
		}
	} else {
		//wait until child completes
		waitpid(pid, &wstatus, 0);
		exit(0);
	}
}

//callback func for SIGSNAPSHOT
void mig_handler(int signo) {
	asylo::Status status;
	
	gettimeofday(&tv, NULL);
	LOG(INFO) << "(" << getpid() << ") SIGSNAPSHOT recv'd: Taking snapshot";

	if (client != NULL) {
		// Take snapshot
		status = client->InitiateMigration();
		status = client->EnterAndTakeSnapshot(&layout);
		if (!status.ok()) {
			LOG(QFATAL) << "InitiateMigration failed";
		}
	}

	asylo::ForkHandshakeConfig fconfig;
	fconfig.set_is_parent(true);
	fconfig.set_socket(0);
	status = client->EnterAndTransferSecureSnapshotKey(fconfig);

	if(!status.ok()) {
		LOG(ERROR) << status << " (" << getpid() << ") Failed to deliver SnapshotKey";
	}
}

void ReloadEnclave(asylo::EnclaveManager *manager, void *base, size_t size)
{
	asylo::Status status;
	// Part 1: Initialization

  // Create an EnclaveLoadConfig object.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name("hello_enclave");

  asylo::EnclaveConfig cfg;
  cfg.set_enable_fork(true);
  //cfg.set_enable_migration(true);

  // Create an SgxLoadConfig object.
  asylo::SgxLoadConfig sgx_config;
  asylo::SgxLoadConfig::ForkConfig fork_config = sgx_config.fork_config();
  fork_config.set_base_address(reinterpret_cast<google::protobuf::uint64>(base));
  LOG(INFO) << "fork_config.set_base_address: " << base;
  asylo::SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
  *sgx_config.mutable_fork_config() = fork_config;
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.mutable_config() = cfg;
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;

  status = manager->LoadEnclave(load_config);
	if (!status.ok()) {
		LOG(QFATAL) << "Load " << absl::GetFlag(FLAGS_enclave_path) << "failed " << status;
	}

	// Verifies that the new enclave is loaded at the same virtual address space as the parent
	client  = dynamic_cast<asylo::primitives::SgxEnclaveClient *>(
      asylo::primitives::Client::GetCurrentClient());
	void *child_enclave_base_address = client->GetBaseAddress();
	if (child_enclave_base_address != base) {
		LOG(ERROR)  << "New enbclave address: " << child_enclave_base_address
					<< " is different from the parent enclav-e address: " << base;
		errno = EAGAIN;
		return;
	} else {
		status = client->InitiateMigration();
		LOG(INFO) << "Reloaded Enclave " << absl::GetFlag(FLAGS_enclave_path);
	}
}

void ResumeExecution(asylo::EnclaveManager *manager)
{
	asylo::Status status;
	client->SetProcessId();
	asylo::ForkHandshakeConfig fconfig;
	fconfig.set_is_parent(false);
	fconfig.set_socket(0);

	status = client->EnterAndTransferSecureSnapshotKey(fconfig);
	if (!status.ok()) {
		LOG(ERROR) << status << " (" << getpid() << ") Failed to deliver SnapshotKey";
	} else {
		LOG(INFO) << "EnterAndRestore";
		status = client->EnterAndRestore(layout);
		if (!status.ok()) {
			LOG(ERROR) << status << "Enclave restore failed & resume from the beginning";
		}
	}

	LOG(INFO) << "Restored enclave";
	gettimeofday(&tve, NULL);

	LOG(INFO) << "( Total time to take snapshot: " << tve.tv_sec - tv.tv_sec << "s " << tve.tv_usec - tv.tv_usec << "usec )";

	// Part 0: setup
	absl::ParseCommandLine(g_argc, g_argv);

	if (absl::GetFlag(FLAGS_names).empty()) {
		LOG(QFATAL) << "Must supply a non-empty list of names with --names";
	}

	std::vector<std::string> names =
		absl::StrSplit(absl::GetFlag(FLAGS_names), ',');

	// Part 2: Secure execution
  asylo::EnclaveClient *client = manager->GetClient("hello_enclave");
	for (const auto &name : names) {
		asylo::EnclaveInput input;
		input.MutableExtension(mig_world::enclave_input_hello)
			->set_to_greet(name);

		asylo::EnclaveOutput output;
		status = client->EnterAndRun(input, &output);
		if (!status.ok()) {
			LOG(QFATAL) << "EnterAndRun failed: " <<status;
		}
		if (!output.HasExtension(mig_world::enclave_output_hello)) {
			LOG(QFATAL) << "Enclave didnot assign an ID for " << name;
		}

		std::cout << "Message from enclave: "
				<< output.GetExtension(mig_world::enclave_output_hello)
						.greeting_message()
				<< std::endl;
	}
}

void Destroy(asylo::EnclaveManager *manager) {
	// Part 3: Finalization
	asylo::Status status;
	asylo::EnclaveFinal final_input;
  asylo::EnclaveClient *client = manager->GetClient("hello_enclave");

	status = manager->DestroyEnclave(client, final_input);
}


int main(int argc, char *argv[]) {

	g_argc = argc;
	g_argv = argv;

	//signal handler for snapshot
	memset(&new_sa, 0, sizeof(new_sa));
	new_sa.sa_handler = mig_handler; // called when the signal is triggered
	sigaction(SIGSNAPSHOT, &new_sa, &old_sa);

	//signal handler for trapping migration at target
	memset(&new_mig_sa, 0, sizeof(new_mig_sa));
	new_mig_sa.sa_handler = initiate_enclave; // called when the signer is triggered
	sigaction(SIGUSR1, &new_mig_sa, &old_mig_sa);

  // Part 0: Setup
  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_names).empty()) {
    LOG(QFATAL) << "Must supply a non-empty list of names with --names";
  }

  std::vector<std::string> names =
      absl::StrSplit(absl::GetFlag(FLAGS_names), ',');

  // Part 1: Initialization
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  if (!manager_result.ok()) {
    LOG(QFATAL) << "EnclaveManager unavailable: " << manager_result.status();
  }
  asylo::EnclaveManager *manager = manager_result.ValueOrDie();
  std::cout << "Loading " << absl::GetFlag(FLAGS_enclave_path) << std::endl;

  // Create an EnclaveLoadConfig object.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name("hello_enclave");

  asylo::EnclaveConfig cfg;
  cfg.set_enable_fork(true);
  //cfg.set_enable_migration(true);

  // Create an SgxLoadConfig object.
  asylo::SgxLoadConfig sgx_config;
  asylo::SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.mutable_config() = cfg;
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;

  asylo::Status status = manager->LoadEnclave(load_config);
  if (!status.ok()) {
    LOG(QFATAL) << "Load " << absl::GetFlag(FLAGS_enclave_path)
                << " failed: " << status;
  }
/*  asylo::primitives::SgxEnclaveClient *sgxclient =
		dynamic_cast<asylo::primitives::SgxEnclaveClient *>(
      asylo::primitives::EnclaveSignalDispatcher::GetInstance()->GetClientForSignal(0));*/

    asylo::GenericEnclaveClient *client_ = reinterpret_cast<asylo::GenericEnclaveClient *>(
        manager->GetClient("hello_enclave"));
	// if it works, primitive_client_ --> client
    std::shared_ptr<asylo::primitives::SgxEnclaveClient> primitive_client_ =
        std::static_pointer_cast<asylo::primitives::SgxEnclaveClient>(
            client_->GetPrimitiveClient());

  LOG(INFO) << "sgxclient: " << primitive_client_;
  enc_base = primitive_client_->GetBaseAddress();
  client = (asylo::primitives::SgxEnclaveClient *)primitive_client_.get();
  LOG(INFO) << "enc_base: " << enc_base;


  // Part 2: Secure execution

  asylo::EnclaveClient *client = manager->GetClient("hello_enclave");
  for (const auto &name : names) {
    asylo::EnclaveInput input;
    input.MutableExtension(mig_world::enclave_input_hello)
        ->set_to_greet(name);

    asylo::EnclaveOutput output;
    status = client->EnterAndRun(input, &output);
    if (!status.ok()) {
      LOG(QFATAL) << "EnterAndRun failed: " << status;
    }

    if (!output.HasExtension(mig_world::enclave_output_hello)) {
      LOG(QFATAL) << "Enclave did not assign an ID for " << name;
    }

    std::cout << "Message from enclave: "
              << output.GetExtension(mig_world::enclave_output_hello)
                     .greeting_message()
              << std::endl;
  }

  // Part 3: Finalization

  asylo::EnclaveFinal final_input;
  status = manager->DestroyEnclave(client, final_input);
  if (!status.ok()) {
    LOG(QFATAL) << "Destroy " << absl::GetFlag(FLAGS_enclave_path)
                << " failed: " << status;
  }

  return 0;
}
