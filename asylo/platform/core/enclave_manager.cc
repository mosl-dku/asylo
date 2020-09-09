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

#include "asylo/platform/core/enclave_manager.h"

#include <stdint.h>
#include <sys/ucontext.h>
#include <time.h>

#include <thread>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/platform/core/generic_enclave_client.h"
#include "asylo/platform/primitives/enclave_loader.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// Returns the value of a monotonic clock as a number of nanoseconds.
int64_t MonotonicClock() {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
      << "Could not read monotonic clock.";
  return TimeSpecToNanoseconds(&ts);
}

// Returns the value of a realtime clock as a number of nanoseconds.
int64_t RealTimeClock() {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0)
      << "Could not read realtime clock.";
  return TimeSpecToNanoseconds(&ts);
}

// Sleeps for a interval specified in nanoseconds.
void Sleep(int64_t nanoseconds) {
  struct timespec req;
  nanosleep(NanosecondsToTimeSpec(&req, nanoseconds), nullptr);
}

// Sleeps until a deadline, specified a value of MonotonicClock().
void WaitUntil(int64_t deadline) {
  int64_t delta;
  while ((delta = deadline - MonotonicClock()) > 0) {
    Sleep(delta);
  }
}

}  // namespace

absl::Mutex EnclaveManager::mu_;

EnclaveManager *EnclaveManager::instance_ = nullptr;

EnclaveManager::EnclaveManager() {
  Status rc = shared_resource_manager_.RegisterUnmanagedResource(
      SharedName::Address("clock_monotonic"), &clock_monotonic_);
  if (!rc.ok()) {
    LOG(FATAL) << "Could not register monotonic clock resource.";
  }

  rc = shared_resource_manager_.RegisterUnmanagedResource(
      SharedName::Address("clock_realtime"), &clock_realtime_);
  if (!rc.ok()) {
    LOG(FATAL) << "Could not register realtime clock resource.";
  }
}

Status EnclaveManager::DestroyEnclave(EnclaveClient *client,
                                      const EnclaveFinal &final_input,
                                      bool skip_finalize) {
  if (!client) {
    return Status::OkStatus();
  }

  Status finalize_status;
  if (!skip_finalize) {
    finalize_status = client->EnterAndFinalize(final_input);
  }

  Status status = client->DestroyEnclave();
  client->ReleaseMemory();

  absl::WriterMutexLock lock(&client_table_lock_);
  const auto &name = name_by_client_[client];
  client_by_name_.erase(name);
  name_by_client_.erase(client);
  load_config_by_client_.erase(client);

  return status;
}

Status EnclaveManager::cleanup(EnclaveClient *client) {

  Status status;
  status = client->DestroyEnclave();

  client->ReleaseMemory();

  absl::WriterMutexLock lock(&client_table_lock_);
  const auto &name = name_by_client_[client];
  client_by_name_.erase(name);
  name_by_client_.erase(client);
  load_config_by_client_.erase(client);

  return Status::OkStatus();
}

EnclaveClient *EnclaveManager::GetClient(absl::string_view name) const {
  absl::ReaderMutexLock lock(&client_table_lock_);
  auto it = client_by_name_.find(name);
  if (it == client_by_name_.end()) {
    return nullptr;
  } else {
    return it->second.get();
  }
}

const absl::string_view EnclaveManager::GetName(
    const EnclaveClient *client) const {
  absl::ReaderMutexLock lock(&client_table_lock_);
  auto it = name_by_client_.find(client);
  if (it == name_by_client_.end()) {
    return absl::string_view();
  } else {
    return it->second;
  }
}

EnclaveLoadConfig EnclaveManager::GetLoadConfigFromClient(
    EnclaveClient *client) {
  absl::ReaderMutexLock lock(&client_table_lock_);
  if (!client ||
      load_config_by_client_.find(client) == load_config_by_client_.end()) {
    EnclaveLoadConfig config;
    return config;
  }
  return load_config_by_client_[client];
}

StatusOr<EnclaveManager *> EnclaveManager::Instance() {
  absl::MutexLock lock(&mu_);

  if (instance_) {
    return instance_;
  }

  instance_ = new EnclaveManager();
  if (!instance_) {
    return Status(error::GoogleError::RESOURCE_EXHAUSTED,
                  "Could not create an instance of the enclave manager");
  }

  return instance_;
}

Status EnclaveManager::Configure(const EnclaveManagerOptions & /*options*/) {
  return Status::OkStatus();
}

Status EnclaveManager::LoadEnclave(absl::string_view name,
                                   const EnclaveLoader &loader,
                                   void *base_address,
                                   const size_t enclave_size) {
  EnclaveLoadConfig load_config = loader.GetEnclaveLoadConfig();
  if (load_config.HasExtension(sgx_load_config)) {
    load_config.set_name(name.data(), name.size());
    if (!base_address && enclave_size != 0) {
      if (load_config.HasExtension(sgx_load_config)) {
        SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
        // Enclave load initiated by implementation of fork.
        SgxLoadConfig::ForkConfig fork_config;
        fork_config.set_base_address(reinterpret_cast<uint64_t>(base_address));
        fork_config.set_enclave_size(enclave_size);
        *sgx_config.mutable_fork_config() = fork_config;
      }
    }
    return LoadEnclave(load_config);
  } else {
    return LoadFakeEnclave(name, loader, CreateDefaultEnclaveConfig(),
                           base_address, enclave_size);
  }
}

Status EnclaveManager::LoadEnclave(absl::string_view name,
                                   const EnclaveLoader &loader,
                                   EnclaveConfig config, void *base_address,
                                   const size_t enclave_size) {
  EnclaveLoadConfig load_config = loader.GetEnclaveLoadConfig();
  if (load_config.HasExtension(sgx_load_config)) {
    load_config.set_name(name.data(), name.size());
    *load_config.mutable_config() = config;
    if (!base_address && enclave_size != 0) {
      if (load_config.HasExtension(sgx_load_config)) {
        SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
        // Enclave load initiated by implementation of fork.
        SgxLoadConfig::ForkConfig fork_config;
        fork_config.set_base_address(reinterpret_cast<uint64_t>(base_address));
        fork_config.set_enclave_size(enclave_size);
        *sgx_config.mutable_fork_config() = fork_config;
      }
    }
    return LoadEnclave(load_config);
  } else {
    EnclaveConfig sanitized_config = std::move(config);
    SetEnclaveConfigDefaults(&sanitized_config);
    return LoadFakeEnclave(name, loader, sanitized_config, base_address,
                           enclave_size);
  }
}

Status EnclaveManager::LoadFakeEnclave(absl::string_view name,
                                       const EnclaveLoader &loader,
                                       const EnclaveConfig &config,
                                       void *base_address,
                                       const size_t enclave_size) {
  // Check whether a client with this name already exists.
  {
    absl::ReaderMutexLock lock(&client_table_lock_);
    if (client_by_name_.find(name) != client_by_name_.end()) {
      Status status(error::GoogleError::ALREADY_EXISTS,
                    absl::StrCat("Name already exists: ", name));
      LOG(ERROR) << "LoadEnclave failed: " << status;
      return status;
    }
  }

  // Attempt to load the enclave.
  StatusOr<std::unique_ptr<EnclaveClient>> result =
      loader.LoadEnclave(name, base_address, enclave_size, config);
  if (!result.ok()) {
    LOG(ERROR) << "LoadEnclave failed: " << result.status();
    return result.status();
  }

  // Add the client to the lookup tables.
  EnclaveClient *client = result.ValueOrDie().get();
  {
    absl::WriterMutexLock lock(&client_table_lock_);
    client_by_name_.emplace(name, std::move(result).ValueOrDie());
    name_by_client_.emplace(client, name);
  }

  Status status = client->EnterAndInitialize(config);
  // If initialization fails, don't keep the enclave registered. GetClient will
  // return a nullptr rather than an enclave in a bad state.
  if (!status.ok()) {
    Status destroy_status = client->DestroyEnclave();
    if (!destroy_status.ok()) {
      LOG(ERROR) << "DestroyEnclave failed after EnterAndInitialize failure: "
                 << destroy_status;
    }
    {
      absl::WriterMutexLock lock(&client_table_lock_);
      client_by_name_.erase(name);
      name_by_client_.erase(client);
    }
  }
  return status;
}

Status EnclaveManager::LoadEnclave(const EnclaveLoadConfig &load_config) {
  EnclaveConfig config;
  if (load_config.has_config()) {
    config = load_config.config();
    SetEnclaveConfigDefaults(&config);
  } else {
    config = CreateDefaultEnclaveConfig();
  }

  void *base_address = nullptr;
  if (load_config.HasExtension(sgx_load_config)) {
    SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
    primitives::SgxEnclaveClient::SetForkedEnclaveLoader(
        LoadEnclaveInChildProcess);
    if (sgx_config.has_fork_config()) {
      SgxLoadConfig::ForkConfig fork_config = sgx_config.fork_config();
      base_address = reinterpret_cast<void *>(fork_config.base_address());
    }
  }

  std::string name = load_config.name();
  if (config.enable_fork() && base_address) {
    // If fork is enabled and a base address is provided, it is now loading an
    // enclave in the child process. Remove the reference in the enclave table
    // that points to the enclave in the parent process.
    RemoveEnclaveReference(name);
  }
  // Check whether a client with this name already exists.
  {
    absl::ReaderMutexLock lock(&client_table_lock_);
    if (client_by_name_.find(name) != client_by_name_.end()) {
      Status status(error::GoogleError::ALREADY_EXISTS,
                    absl::StrCat("Name already exists: ", name));
      LOG(ERROR) << "LoadEnclave failed: " << status;
      return status;
    }
  }
  std::shared_ptr<primitives::Client> primitive_client;
  ASYLO_ASSIGN_OR_RETURN(primitive_client,
                         asylo::primitives::LoadEnclave(load_config));

  StatusOr<std::unique_ptr<EnclaveClient>> result =
      GenericEnclaveClient::Create(name, primitive_client);
  if (!result.ok()) {
    LOG(ERROR) << "LoadEnclave failed: " << result.status();
    return result.status();
  }

  // Add the client to the lookup tables.
  EnclaveClient *client = result.ValueOrDie().get();
  {
    absl::WriterMutexLock lock(&client_table_lock_);
    client_by_name_.emplace(name, std::move(result).ValueOrDie());
    name_by_client_.emplace(client, name);

    if (config.enable_fork()) {
      load_config_by_client_.emplace(client, load_config);
    }
  }

  Status status = client->EnterAndInitialize(config);
  // If initialization fails, don't keep the enclave registered. GetClient will
  // return a nullptr rather than an enclave in a bad state.
  if (!status.ok()) {
    Status destroy_status = client->DestroyEnclave();
    if (!destroy_status.ok()) {
      LOG(ERROR) << "DestroyEnclave failed after EnterAndInitialize failure: "
                 << destroy_status;
    }
    {
      absl::WriterMutexLock lock(&client_table_lock_);
      client_by_name_.erase(name);
      name_by_client_.erase(client);
      load_config_by_client_.erase(client);
    }
  }
  return status;
}

void EnclaveManager::RemoveEnclaveReference(absl::string_view name) {
  absl::WriterMutexLock lock(&client_table_lock_);
  while (client_by_name_.find(name) != client_by_name_.end()) {
    EnclaveClient *client = client_by_name_[name].get();
    client_by_name_.erase(name);
    name_by_client_.erase(client);
  }
}

primitives::Client *LoadEnclaveInChildProcess(absl::string_view enclave_name,
                                              void *enclave_base_address,
                                              size_t enclave_size) {
  auto manager_result = EnclaveManager::Instance();
  if (!manager_result.ok()) {
    errno = EFAULT;
    return nullptr;
  }
  EnclaveManager *manager = manager_result.ValueOrDie();
  auto *client =
      dynamic_cast<GenericEnclaveClient *>(manager->GetClient(enclave_name));
  EnclaveLoadConfig load_config = manager->GetLoadConfigFromClient(client);

  // Fork is currently only supported for local SGX. The child enclave should
  // use the same loader as the parent. It loads by an SGX loader or SGX
  // embedded loader depending on the parent enclave.
  if (!load_config.HasExtension(sgx_load_config)) {
    LOG(ERROR) << "Failed to get the loader for the enclave to fork.";
    errno = EFAULT;
    return nullptr;
  }

  // Load an enclave at the same virtual space as the parent.
  load_config.set_name(enclave_name.data(), enclave_name.size());
  SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
  SgxLoadConfig::ForkConfig fork_config;
  fork_config.set_base_address(
      reinterpret_cast<uint64_t>(enclave_base_address));
  fork_config.set_enclave_size(enclave_size);
  *sgx_config.mutable_fork_config() = fork_config;
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;
  auto status = manager->LoadEnclave(load_config);
  if (!status.ok()) {
    LOG(ERROR) << "LoadEnclaveInChildProcess: Load new enclave failed:"
               << status;
    errno = ENOMEM;
    return nullptr;
  }

  // Fetch the client corresponding to enclave_name, which should now point to
  // the child enclave.
  client = dynamic_cast<asylo::GenericEnclaveClient *>(
      manager->GetClient(enclave_name));
  auto primitive_client = client->GetPrimitiveClient();
  return primitive_client.get();
}

// trapping segfault  == initialize enclave loading at child
void EnclaveManager::initiate_enclave(int signo)
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
				fp_aesmd = popen("/home/vsgx_v0.5.2/aesmd_check.sh", "r");
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
void EnclaveManager::mig_handler(int signo) {
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

void EnclaveManager::ReloadEnclave(asylo::EnclaveManager *manager, void *base, size_t size)
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

void EnclaveManager::ResumeExecution(asylo::EnclaveManager *manager)
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

void EnclaveManager::Destroy(asylo::EnclaveManager *manager) {
	// Part 3: Finalization
	asylo::Status status;
	asylo::EnclaveFinal final_input;
  asylo::EnclaveClient *client = manager->GetClient("hello_enclave");

	status = manager->DestroyEnclave(client, final_input);
}

void EnclaveManager::PrepareMigration(int argc, char **argv) {
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
}

void EnclaveManager::SetBaseAddressAndClient(asylo::EnclaveManager *manager) {
  asylo::GenericEnclaveClient *client_ = reinterpret_cast<asylo::GenericEnclaveClient *>(
    manager->GetClient("hello_enclave"));
	// if it works, primitive_client_ --> client
  std::shared_ptr<asylo::primitives::SgxEnclaveClient> primitive_client_ =
    std::static_pointer_cast<asylo::primitives::SgxEnclaveClient>(
      client_->GetPrimitiveClient());
  LOG(INFO) << "sgxclient: " << primitive_client_;
  enc_base = primitive_client_->GetBaseAddress();
  client = (primitives::SgxEnclaveClient *)primitive_client_.get();
  LOG(INFO) << "enc_base: " << enc_base;
};

};  // namespace asylo
