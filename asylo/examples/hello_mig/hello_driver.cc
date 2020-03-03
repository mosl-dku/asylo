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
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/time.h>

#define SIGSNAPSHOT SIGUSR2

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_split.h"
#include "asylo/client.h"
#include "asylo/examples/hello_mig/hello.pb.h"
#include "asylo/util/logging.h"

#include "asylo/platform/arch/fork.pb.h"
#include "asylo/platform/common/memory.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(std::string, names, "",
          "A comma-separated list of names to pass to the enclave");

// some global var
asylo::SgxClient *client;
void *enc_base;
size_t enc_size;
int g_argc;
char **g_argv;
asylo::SnapshotLayout layout;
struct sigaction old_sa;
struct sigaction new_sa;
struct sigaction old_mig_sa;
struct sigaction new_mig_sa;

struct timeval tv;
struct timeval tve;

// some func defs
void ReloadEnclave(asylo::EnclaveManager *manager, void *base, size_t size);
void ResumeExecution(asylo::EnclaveManager *manager);
void Destroy(asylo::EnclaveManager *manager);
asylo::EnclaveConfig GetApplicationConfig();

// trapping segfault == initiate enclave loading at child
void initiate_enclave(int signo) {

  int wstatus;
  int pid = fork();
  if (pid < 0) {
	LOG(FATAL) <<"fork failed";
  } else if (pid == 0) {
	pid = fork();

	if (pid < 0) {
	  LOG(FATAL) <<"fork failed";
	} else if (pid > 0) {
		// wait a second for restarting aesmd service exec
	  sleep(1);
      asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
      auto manager_result = asylo::EnclaveManager::Instance();
      if (!manager_result.ok()) {
        LOG(QFATAL) << "EnclaveManager unavailable: " << manager_result.status();
      }
      asylo::EnclaveManager *manager = manager_result.ValueOrDie();

      // now, reload enclave, then restore snapshot from migration
      ReloadEnclave(manager, enc_base, enc_size);

      ResumeExecution(manager);
      Destroy(manager);

      exit(0);
      // never reach here
      return;
	} else {
		// child exec. restart aesmd service
        execl("/usr/bin/sudo", "sudo", "service", "aesmd", "restart", 0);
		exit(0);
	}

  } else {
	// wait until child completes
    waitpid(pid, &wstatus, NULL);
    exit(0);
  }
}

// callback for SIGSNAPSHOT
void mig_handler(int signo) {

  gettimeofday(&tv, NULL);
  LOG(INFO) << "(" << getpid() << ") SIGSNAPSHOT recv'd: Taking snapshot";

  if (client != NULL) {
    //Take snapshot
    asylo::Status status = client->InitiateMigration();
    status = client->EnterAndTakeSnapshot(&layout);
	if (!status.ok()) {
	  LOG(QFATAL) << "InitiateMigration failed";
	}
  }

    asylo::ForkHandshakeConfig fconfig;
    fconfig.set_is_parent(true);
    fconfig.set_socket(0);
    asylo::Status status = client->EnterAndTransferSecureSnapshotKey(fconfig);
    if (!status.ok()) {
		LOG(ERROR) << status << " (" << getpid() << ") Failed to deliver SnapshotKey";
    }

}

void ReloadEnclave(asylo::EnclaveManager *manager, void *base, size_t size) {

  asylo::Status status;
  // Part 1: Initialization
  asylo::EnclaveLoader *loader = manager->GetLoaderFromClient(client);
  asylo::EnclaveConfig config = GetApplicationConfig();
  config.set_enable_fork(true);
  config.set_enable_migration(true);
  status = manager->LoadEnclave("hello_enclave", *loader, config, base, size);
  if (!status.ok()) {
    LOG(QFATAL) << "Load " << absl::GetFlag(FLAGS_enclave_path)
                << " failed: " << status;
  }
  // Verifies that the new enclave is loaded at the same virtual address space
  // as the parent enclave.
  client = dynamic_cast<asylo::SgxClient *>(manager->GetClient("hello_enclave"));
  void *child_enclave_base_address = client->base_address();
  if (child_enclave_base_address != base) {
    LOG(ERROR) << "New enclave address: " << child_enclave_base_address
               << " is different from the parent enclave address: "
               << base;
    errno = EAGAIN;
    return ;
  } else {
    asylo::Status status = client->InitiateMigration();
	LOG(INFO) << "Reloaded Enclave "<< absl::GetFlag(FLAGS_enclave_path) ;
  }
}

void ResumeExecution(asylo::EnclaveManager *manager) {

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

  LOG(INFO) << "Restored Enclave";
  gettimeofday(&tve, NULL);
  LOG(INFO) << "( " <<  "Total time to take snapshot : " << tve.tv_sec - tv.tv_sec << " sec " << tve.tv_usec - tv.tv_usec << " usec )";

  // Part 0: Setup
  absl::ParseCommandLine(g_argc, g_argv);

  if (absl::GetFlag(FLAGS_names).empty()) {
    LOG(QFATAL) << "Must supply a non-empty list of names with --names";
  }

  std::vector<std::string> names =
      absl::StrSplit(absl::GetFlag(FLAGS_names), ',');


  // Part 2: Secure execution
  client = reinterpret_cast<asylo::SgxClient *>(manager->GetClient("hello_enclave"));

  for (const auto &name : names) {
    asylo::EnclaveInput input;
    input.MutableExtension(hello_world::enclave_input_hello)
        ->set_to_greet(name);

    asylo::EnclaveOutput output;
    asylo::Status status = client->EnterAndRun(input, &output);
    if (!status.ok()) {
      LOG(QFATAL) << "EnterAndRun failed: " << status;
    }

    if (!output.HasExtension(hello_world::enclave_output_hello)) {
      LOG(QFATAL) << "Enclave did not assign an ID for " << name;
    }

    std::cout << "Message from enclave: "
              << output.GetExtension(hello_world::enclave_output_hello)
                     .greeting_message()
              << std::endl;
  }

}

void Destroy(asylo::EnclaveManager *manager) {

  // Part 3: Finalization

  asylo::Status status;
  asylo::EnclaveFinal final_input;
  status = manager->DestroyEnclave(client, final_input, 0);
}

int main(int argc, char *argv[]) {

  g_argc = argc;
  g_argv = argv;
  // signal handler for takesnapshot
  memset(&new_sa, 0, sizeof(new_sa));
  new_sa.sa_handler = mig_handler; // called when the signal is triggered
  sigaction(SIGSNAPSHOT, &new_sa, &old_sa);

  // signal handler for trapping migration at target
  memset(&new_mig_sa, 0, sizeof(new_sa));
  new_mig_sa.sa_handler = initiate_enclave; // called when the signal is triggered
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

  asylo::EnclaveConfig config = GetApplicationConfig();
  config.set_enable_fork(true);
  config.set_enable_migration(true);

  asylo::SgxLoader loader(absl::GetFlag(FLAGS_enclave_path), /*debug=*/true);
  asylo::Status status = manager->LoadEnclave("hello_enclave", loader, config);
  if (!status.ok()) {
    LOG(QFATAL) << "Load " << absl::GetFlag(FLAGS_enclave_path)
                << " failed: " << status;
  }

  // Part 2: Secure execution
  client = reinterpret_cast<asylo::SgxClient *>(manager->GetClient("hello_enclave"));

  enc_base = client->base_address();
  enc_size = client->size();

  for (const auto &name : names) {
    asylo::EnclaveInput input;
    input.MutableExtension(hello_world::enclave_input_hello)
        ->set_to_greet(name);

    asylo::EnclaveOutput output;
    status = client->EnterAndRun(input, &output);
    if (!status.ok()) {
      LOG(QFATAL) << "EnterAndRun failed: " << status;
    }

    if (!output.HasExtension(hello_world::enclave_output_hello)) {
      LOG(QFATAL) << "Enclave did not assign an ID for " << name;
    }

    std::cout << "Message from enclave: "
              << output.GetExtension(hello_world::enclave_output_hello)
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
