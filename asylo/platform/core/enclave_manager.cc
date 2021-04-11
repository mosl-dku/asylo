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
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/platform/core/generic_enclave_client.h"
#include "asylo/platform/primitives/enclave_loader.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
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

	struct sigaction new_suspend_sa;
	struct sigaction new_resume_sa;

	// mig-signal handler from OS
	memset(&old_suspend_sa, 0, sizeof(struct sigaction));
	memset(&new_suspend_sa, 0, sizeof(struct sigaction));
	memset(&old_resume_sa, 0, sizeof(struct sigaction));
	memset(&new_resume_sa, 0, sizeof(struct sigaction));

	new_suspend_sa.sa_handler = EnclaveManager::__asylo_sig_mig_suspend;
	new_resume_sa.sa_handler = EnclaveManager::__asylo_sig_mig_resume;

	sigaction(SIGUSR2, &new_suspend_sa, &old_suspend_sa);
	sigaction(SIGUSR1, &new_resume_sa, &old_resume_sa);
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

	struct sigaction tmp1;
	struct sigaction tmp2;
	struct sigaction tmp;
	sigaction(SIGUSR2, &old_suspend_sa, &tmp1);
	sigaction(SIGUSR1, &old_resume_sa, &tmp2);

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
  snapshot_by_client_.erase(client);

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
			snapshot_by_client_.erase(client);
    }
  }
  return status;
}

Status EnclaveManager::ReloadEnclave(absl::string_view name,
																			EnclaveClient * client,
																			EnclaveLoadConfig config) {
	LOG(INFO) << "Reload Enclave, " << name;
	Status s;
  {
		absl::WriterMutexLock lock(&client_table_lock_);
		client_by_name_.erase(name);
		name_by_client_.erase(client);
		load_config_by_client_.erase(client);
		snapshot_by_client_.erase(client);
  }

	s = LoadEnclave(config);
	LOG(INFO) << "Reload: " << s;

	return s;
}

void EnclaveManager::RemoveEnclaveReference(absl::string_view name) {
  absl::WriterMutexLock lock(&client_table_lock_);
  while (client_by_name_.find(name) != client_by_name_.end()) {
    EnclaveClient *client = client_by_name_[name].get();
    client_by_name_.erase(name);
    name_by_client_.erase(client);
  }
}

void EnclaveManager::__asylo_sig_mig_suspend(int signo) {
	std::cout << "===  sig_mig_suspend  ===" << std::endl;
  auto manager_result = EnclaveManager::Instance();
  if (!manager_result.ok()) {
		LOG(INFO) << "cannot find EnclaveManager";
    return;
  }
  EnclaveManager *manager = manager_result.ValueOrDie();
	manager->TakeSnapshot();
}

void EnclaveManager::TakeSnapshot() {
	Status s;
	for (const auto & c : client_by_name_) {
		// for all clients,
  auto *client = reinterpret_cast<asylo::GenericEnclaveClient *>(
      this->GetClient(c.first));
	// obtain primitive_client
	std::shared_ptr<asylo::primitives::SgxEnclaveClient> sgx_client =
			std::static_pointer_cast<asylo::primitives::SgxEnclaveClient>(
				client->GetPrimitiveClient());
	//asylo::primitives::SgxEnclaveClient* sgx_client =
	//	(asylo::primitives::SgxEnclaveClient *)(
	//		(std::dynamic_pointer_cast<asylo::primitives::SgxEnclaveClient>(client->GetPrimitiveClient()))->get());

	// InitiateMigration()
	SnapshotLayout * snapshot_layout = new SnapshotLayout();
	s = sgx_client->InitiateMigration();
	if (!s.ok()) {
		LOG(QFATAL) << "Init Migration Failed " << s;
	} else {
		LOG(INFO) << "InitMigration " << s;
	}
	snapshot_by_client_.emplace(client, snapshot_layout);
	LOG(INFO) << "employ snapshot (" << snapshot_layout << ") " ;

	// TakeSnapshot()
	s = sgx_client->EnterAndTakeSnapshot(snapshot_layout);
	if (!s.ok()) {
		LOG(QFATAL) << "Take snapshot Failed " << s;
	} else {
		asylo::EnclaveFinal final_input;
		LOG(INFO) << "Take snapshot Succeed - now we got the snapshot";
		// TO-DO: under migration, we may need to destroy the enclave
		//cleanup(client);
	}
	asylo::ForkHandshakeConfig fconfig;
	fconfig.set_is_parent(true);
	fconfig.set_socket(0);
	s = sgx_client->EnterAndTransferSecureSnapshotKey(fconfig);
	if (!s.ok()) {
		LOG(QFATAL) << "@source TransferSecureSnapshotKey failed: " << s;
	} else {
		LOG(INFO) << "@source TansferSecureSnapshotKey " << s;
	}

	} // end for

}

void EnclaveManager::SuspendClients() {
	Status s;
	for (const auto & c : client_by_name_) {
		// for all clients,
  auto *client = dynamic_cast<asylo::GenericEnclaveClient *>(
      this->GetClient(c.first));
	// obtain primitive_client
	std::shared_ptr<asylo::primitives::SgxEnclaveClient> sgx_client =
		std::static_pointer_cast< asylo::primitives::SgxEnclaveClient> (
			client->GetPrimitiveClient());

	// InitiateMigration()
	SnapshotLayout *playout = new SnapshotLayout();
	s = sgx_client->InitiateMigration(playout);
	if (!s.ok()) {
		LOG(QFATAL) << "Init Migration Failed ";
	} else {
		LOG(INFO) << "Init Migration Succeed  - now enclave suspend";
	}

	snapshot_by_client_.emplace(client, playout);
	} // end for
}

void EnclaveManager::__asylo_sig_mig_resume(int signo) {
	std::cout << "===  sig_mig_resume  ===" << std::endl;
  auto manager_result = EnclaveManager::Instance();
  if (!manager_result.ok()) {
		LOG(INFO) << "cannot find EnclaveManager";
    return;
  }
  EnclaveManager *manager = manager_result.ValueOrDie();
	manager->ReloadEnclaves();
}

void EnclaveManager::ReloadEnclaves() {
	// After the migration,
	// 1. check aesmd is ready
	// 2. reload the enclave
	// 3. restore and resume the enclave

	Status s;
	// check the aesmd status
	FILE *fp_aesmd = NULL;
	char buff_aesmd[2];
	while (1) {
		fp_aesmd = popen("/usr/script/aesmd_check.sh", "r");
		if (fp_aesmd == NULL) {
			LOG(FATAL) << "popen failed";
			break;
		}
		fgets(buff_aesmd, 2, fp_aesmd);
		fclose(fp_aesmd);

		if (strcmp(buff_aesmd, "1"))
			LOG(INFO) << "waiting for aesmd restart...";
		else {
			LOG(INFO) << "aesmd is restarted & ready";
			break;
		}
	}
	usleep (70000);

	// Reload enclaves
	for (const auto & c : client_by_name_) {
		// for all clients;
		auto * client  = reinterpret_cast<asylo::GenericEnclaveClient *>(
			this->GetClient(c.first));

		auto config = load_config_by_client_.find(client);
		//ReloadEnclave(c.first, client, config->second);

		std::shared_ptr<asylo::primitives::SgxEnclaveClient> sgx_client =
			std::static_pointer_cast<asylo::primitives::SgxEnclaveClient>(
				client->GetPrimitiveClient());

		auto result = snapshot_by_client_.find(client);
		SnapshotLayout *playout = result->second;
		asylo::ForkHandshakeConfig fconfig;
		fconfig.set_is_parent(false);
		fconfig.set_socket(0);
		s = sgx_client->EnterAndTransferSecureSnapshotKey(fconfig);
		if (!s.ok()) {
			LOG(QFATAL) << "@target TransferSecureSnapshotKey failed: " << s;
		} else {
			LOG(INFO) << "@target TransferSecureSnapshotKey ( " << playout << " ) " << s;
		}

		s = sgx_client->EnterAndRestore(*playout);
		if (!s.ok()) {
			LOG(QFATAL) << "Restore Enclave failed: " << s;
		} else {
			LOG(INFO) << "Restore Enclave " << s;
		}
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


};  // namespace asylo
