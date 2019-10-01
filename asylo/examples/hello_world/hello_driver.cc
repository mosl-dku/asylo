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
#include <sys/wait.h>
#include <unistd.h>

#include "absl/strings/str_split.h"
#include "asylo/client.h"
#include "asylo/examples/hello_world/hello.pb.h"
#include "gflags/gflags.h"

#include "asylo/util/logging.h"
#include "asylo/platform/arch/fork.pb.h"
#include "asylo/platform/common/memory.h"

DEFINE_string(enclave_path, "", "Path to enclave to load");
DEFINE_string(names, "",
              "A comma-separated list of names to pass to the enclave");

asylo::EnclaveConfig GetApplicationConfig();

asylo::Status status; 
asylo::EnclaveManager *manager;
asylo::EnclaveClient *client;

struct sigaction old_sa;
struct sigaction new_sa;
int hello(int, char** );
int g_argc;
char **g_argv;
pid_t pid;
int wstatus;

void signal_handler(int signo)
{
	LOG(INFO)<<"SIGUSR1 Received : Restart main\n";
/*	asylo::EnclaveFinal final_input;
	status = manager->DestroyEnclave(client, final_input);
	if (!status.ok()) {
	  LOG(QFATAL) << "Destroy " << FLAGS_enclave_path << " failed: " << status;
	}
	LOG_IF(INFO, status.ok()) << "FIN";*/

	pid = fork();

	if(pid < 0)
	{
		perror("fork error");
	}
	else if(pid == 0) //child
	{
		execl("/usr/sbin/service", "aesmd", "restart", 0);
		exit(0);
	}
	else // parent
	{
		pid = fork();

		if(pid < 0)
		{
			perror("fork error");
		}
		else if(pid == 0) //child
		{
			hello(g_argc, g_argv);
			exit(0);
		}
		else // parent
		{
			waitpid(pid, &wstatus, NULL);
			exit(0);
		}
	}
}

int main(int argc, char*argv[]){
	g_argc = argc;
	g_argv = argv;
	memset(&new_sa, 0, sizeof(new_sa));
	new_sa.sa_handler=&signal_handler;
	sigaction(SIGUSR1,&new_sa,&old_sa);	
	hello(argc, argv);
} 

int hello(int argc, char *argv[]) {
  // Part 0: Setup
  ::google::ParseCommandLineFlags(&argc, &argv,
                                  /*remove_flags=*/true);

  if (FLAGS_names.empty()) {
    LOG(QFATAL) << "Must supply a non-empty list of names with --names";
  }

  std::vector<std::string> names = absl::StrSplit(FLAGS_names, ',');

  // Part 1: Initialization
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  if (!manager_result.ok()) {
    LOG(QFATAL) << "EnclaveManager unavailable: " << manager_result.status();
  }
  asylo::EnclaveConfig config = GetApplicationConfig();
  config.set_enable_fork(true);

  //asylo::EnclaveManager *manager = manager_result.ValueOrDie();
  manager = manager_result.ValueOrDie();
  std::cout << "Loading " << FLAGS_enclave_path << std::endl;
  asylo::SgxLoader loader(FLAGS_enclave_path, /*debug=*/true);
  void *addr = (void *)0x7fdbcc000000;
  size_t sz = 33554432;
  LOG(INFO) << "base: " << addr << " sz: " << sz;
  //asylo::Status status = manager->LoadEnclave("hello_enclave", loader, config, addr, sz);
  status = manager->LoadEnclave("hello_enclave", loader, config, addr, sz);
  if (!status.ok()) {
    LOG(QFATAL) << "Load " << FLAGS_enclave_path << " failed: " << status;
  }

  // Part 2: Secure execution

  //asylo::EnclaveClient *client = manager->GetClient("hello_enclave");
  //asylo::SgxClient *client = reinterpret_cast<asylo::SgxClient *>(manager->GetClient("hello_enclave"));
  client = reinterpret_cast<asylo::SgxClient *>(manager->GetClient("hello_enclave"));

  for (const auto &name : names) {
    asylo::EnclaveInput input;
    input.MutableExtension(hello_world::enclave_input_hello)
        ->set_to_greet(name);

    //asylo::EnclaveOutput output;
    asylo::EnclaveOutput* output = new asylo::EnclaveOutput();
    status = client->EnterAndRun(input, output);

    if (!status.ok()) {
      LOG(QFATAL) << "EnterAndRun failed: " << status;
    }
    if (!output->HasExtension(hello_world::enclave_output_hello)) {
    	std::cout << " output " <<
		  output->GetExtension(hello_world::enclave_output_hello).greeting_message()
		  << "\n input " <<
		  input.GetExtension(hello_world::enclave_input_hello).to_greet()
		  << std::endl;
      LOG(QFATAL) << "Enclave did not assign an ID for " << name;
    }
	std::cout << "Message from enclave: "
              << output->GetExtension(hello_world::enclave_output_hello)
                     .greeting_message()
              << std::endl;
  }
/*
  // Part 2.1 Take snapshot
  status = client->EnterAndTakeSnapshot(&snapshot_layout_);
	LOG_IF(INFO, status.ok())
      << "Snapshot " << FLAGS_enclave_path << " : " << snapshot_layout_.data_size() << " ldh ";
	LOG_IF(INFO, !status.ok())
      << "Snapshot " << FLAGS_enclave_path << " failed : " << status;
	snapshot_deleter_.Reset(snapshot_layout_);


  // Part 2.2 Restore from snapshot
  status = client->EnterAndRestore(snapshot_layout_);
  LOG_IF(INFO, status.ok())
      << "Restore " << FLAGS_enclave_path << " : " << status << " ldh ";
  LOG_IF(QFATAL, !status.ok())
      << "Restore " << FLAGS_enclave_path << " failed : " << status;
*/
  // Part 3: Finalization

  asylo::EnclaveFinal final_input;
  status = manager->DestroyEnclave(client, final_input);
  if (!status.ok()) {
    LOG(QFATAL) << "Destroy " << FLAGS_enclave_path << " failed: " << status;
  }
  LOG_IF(INFO, status.ok()) << "FIN";

  _exit(0);
  return 0;
}
