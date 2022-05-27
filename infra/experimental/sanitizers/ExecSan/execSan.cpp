/*
 * Copyright 2022 Google LLC

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *      http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/* A detector that uses ptrace to identify shell injection vulnerabilities. */

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* POSIX */
#include <unistd.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

#include <fstream>
#include <string>
#include <mutex>
#include <thread>
#include <vector>

const std::string kTripWire = "/tmp/tripwire";

std::vector<std::thread> g_threads;
std::mutex g_threads_mutex;


#define FATAL(...) \
    do { \
        fprintf(stderr, "execSan: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

pid_t run_child(char **argv) {
  // Run the program under test with its args as a child process
  pid_t pid = fork();
  switch (pid) {
    case -1: /* error */
      FATAL("Fork failed: %s", strerror(errno));
    case 0:  /* child */
      raise(SIGTRAP);
      //ptrace(PTRACE_TRACEME, 0, 0, 0);
      /* Because we're now a tracee, execvp will block until the parent
       * attaches and allows us to continue. */
      execv(argv[1], argv + 1);
      FATAL("execv: %s", strerror(errno));
  }
  return pid;
}

std::vector<std::byte> read_memory(pid_t pid, unsigned long long address, size_t size) {
  std::vector<std::byte> memory;

  for (size_t i = 0; i < size; i += sizeof(long)) {
    long word = ptrace(PTRACE_PEEKTEXT, pid, address + i, 0);
    if (word == -1) {
      return memory;
    }

    std::byte *word_bytes = reinterpret_cast<std::byte*>(&word);
    memory.insert(memory.end(), word_bytes, word_bytes+sizeof(long));
  }

  return memory;
}

void inspect(pid_t pid, const user_regs_struct &regs) {
  auto memory = read_memory(pid, regs.rdi, kTripWire.length());
  if (memory.size() == 0) {
    return;
  }

  std::string path(reinterpret_cast<char*>(
        memory.data()), std::min(memory.size(), kTripWire.length()));
  printf("inspecting\n");
  if (path == kTripWire) {
    ptrace(PTRACE_KILL, pid, nullptr, nullptr);
    printf("===BUG DETECTED: Shell injection===\n");
    exit(1);
  }
}

void trace_syscall(pid_t pid) {
  if (waitpid(pid, nullptr, __WALL) == -1) {
    printf("waitpid: %s", strerror(errno));
    fflush(stdout);
  }

  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
    FATAL("ptrace(PTRACE_SYSCALL): %s", strerror(errno));
  }

  while (true) {
      int status;
      printf("waiting %d\n", pid);
      fflush(stdout);
      if (waitpid(pid, &status, __WALL) == -1) {
        printf("waitpid: %s", strerror(errno));
        fflush(stdout);
        //return;
      }

      printf("finished waiting %d\n", pid);
      fflush(stdout);

      if ((status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))) {
          printf("exec\n");
          fflush(stdout);
      }

      if ((status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8)))) {
          printf("exit %ld\n", pid);
          fflush(stdout);
      }

      bool is_syscall = WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80);
      int sig = 0;
      if (!is_syscall) {
        siginfo_t siginfo;
        if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &siginfo) == -1) {
          FATAL("ptrace(PTRACE_GETSIGINFO): %s", strerror(errno));
        }
        sig = siginfo.si_signo;
        printf("forwarding %d\n", sig);
        fflush(stdout);
      }

      if (WIFSTOPPED(status) && 
          (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) ||
           status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)) ||
           status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)))) {
          printf("forked\n");
          fflush(stdout);
          
          // Forked.
          long new_pid;
          if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) == -1) {
            FATAL("ptrace(PTRACE_GETEVENTMSG): %s", strerror(errno));
          }
          printf("forked %d\n", new_pid);

          {
            std::lock_guard<std::mutex> guard(g_threads_mutex);
            g_threads.emplace_back(trace_syscall, new_pid);
          }
      }

      if (WIFEXITED(status)) {
        return;
      }

      if (is_syscall) {
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
          printf("ptrace(PTRACE_GETREGS): %s", strerror(errno));
          fflush(stdout);
          return;
        }

        if (regs.orig_rax == __NR_execve) {
          inspect(pid, regs);
        }
      }

      printf("tracing %ld %d\n", pid, sig);
      fflush(stdout);
      if (ptrace(PTRACE_SYSCALL, pid, nullptr, sig) == -1) {
        printf("ptrace(PTRACE_SYSCALL): %ld, %s", pid, strerror(errno));
        fflush(stdout);
        return;
      }
    }
}

int main(int argc, char **argv) {
  if (argc <= 1)
    FATAL("Expecting at least one arguments, received %d", argc - 1);

  // Create tripwire file, as programs may check for existence before
  // executing.
  std::ofstream tripwire(kTripWire);
  tripwire.close();
  chmod(kTripWire.c_str(), 0755);

  pid_t pid = run_child(argv);

  long data = 
    PTRACE_O_TRACESYSGOOD
      | PTRACE_O_TRACEEXEC
      | PTRACE_O_TRACEEXIT
      | PTRACE_O_TRACEFORK
      | PTRACE_O_TRACEVFORK
      | PTRACE_O_TRACECLONE
      ;

  // sync with child process
  if (ptrace(PTRACE_SEIZE, pid, nullptr, data) == -1)
    FATAL("ptrace(PTRACE_SEIZE): %s", strerror(errno));

  trace_syscall(pid);
}
