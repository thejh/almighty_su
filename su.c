/*
** Copyright 2012, Jann Horn <jannhorn@googlemail.com>
** Copyright 2010, Adam Shanks (@ChainsDD)
** Copyright 2008, Zinx Verituse (@zinxv)
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
**
**
** This file compiles to the "su" setuid executable. It is designed to run for a
** maximum of a few seconds, so memory is never freed for speed and safety - you
** can introduce security-relevant bugs by free()ing variables, but just leaving
** stuff in memory should always be fine. Hmm, I really like how the lines in my
** header all have the same length - in a fixed-width font, it looks really nice
** 
** A few parts of this code were ripped from ChainsDD's su, but most of it was
** rewritten by Jann Horn.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <pwd.h>
#include <sys/prctl.h>

enum uid_state { STATE_ALLOWED, STATE_DENIED, STATE_UNDEFINED };

void err(char *str) {
  fputs(str, stderr);
  exit(1);
}

int get_uid_state(int uid) {
  if (uid == 0) return STATE_ALLOWED; // short-circuit for root
  
  char *file_path;
  if (asprintf(&file_path, "/data/data/thejh.almighty/uid_ok/uid:%i", uid) < 0) err("allocation fail");
  FILE *f = fopen(file_path, "r");
  if (f == NULL) return STATE_UNDEFINED;
  int c = fgetc(f);
  if (fclose(f) != 0) err("can't close uid:-file");
  return (c == 'A') ? STATE_ALLOWED : STATE_DENIED;
}

int get_own_app_uid() {
  struct stat s;
  if (stat("/data/data/thejh.almighty", &s) != 0) err("stat() on almighty app's directory failed");
  if (s.st_uid != s.st_gid) err("stat() returned weird data dir owner info");
  return s.st_uid;
}

void usage() {
  fprintf(stderr,
  "Usage: su [options] [--] [-] [LOGIN] [--] [args...]\n\n"
  "Options:\n"
  "  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
  "  -h, --help                    display this help message and exit\n"
  "  -, -l, --login                pretend the shell to be a login shell\n"
  "  -m, -p,\n"
  "  --preserve-environment        do not change environment variables\n"
  "  -s, --shell SHELL             use SHELL instead of the default\n"
  "  -v, --version                 display version number and exit\n"
  "  -V                            display version code and exit (for internal use)\n");
}

// fire-and-forget
void send_request_intent(int uid, int pid) {
  char *cmd;
  if (asprintf(&cmd, "/system/bin/am start --ei pid %i --ei uid %i thejh.almighty/.AskPermissionActivity > /dev/null", pid, uid) < 0)
    err("alloc failed");
  clearenv();
  setenv("LD_LIBRARY_PATH", "/vendor/lib:/system/lib", 1);
  setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
  setenv("BOOTCLASSPATH", "/system/framework/core.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/android.policy.jar:/system/framework/services.jar", 1);
  system(cmd);
}

int main(int argc, char *argv[]) {
  char *command = NULL, *shell = "/system/bin/sh";
  int is_login_shell = 0, preserve_env = 0;
  int wanted_uid = 0; // let's assume everyone is mad for power
  
  struct option long_opts[] = {
    { "command",              required_argument, NULL, 'c' },
    { "help",	                no_argument,       NULL, 'h' },
    { "login",                no_argument,       NULL, 'l' },
    { "preserve-environment", no_argument,       NULL, 'p' },
    { "shell",                required_argument, NULL, 's' },
    { "version",              no_argument,       NULL, 'v' },
    { NULL,                   0,                 NULL, 0   }
  };
  int c;
  while ((c = getopt_long(argc, argv, "+c:hlmps:Vv", long_opts, NULL)) != -1) {
    switch (c) {
      /* instant-exit options */
      case 'h':
        usage();
        exit(0);
      case 'V':
        puts("almighty-1.0");
        exit(0);
      case 'v':
        puts("almighty-1");
        exit(0);
      
      /* normal options */
      case 'c':
        command = optarg;
        break;
      case 'l':
        is_login_shell = 1;
        break;
      case 'm': case 'p':
        preserve_env = 1;
        break;
      case 's':
        shell = optarg;
        break;
      
      default:
        fprintf(stderr, "ERROR: unimplemented or unknown option encountered: %hhi\n", c);
        usage();
        exit(1);
    }
  }
  
  if (optind < argc && strcmp(argv[optind], "-") == 0) {
    is_login_shell = 1;
    optind++;
  }
  
  if (optind < argc && strcmp(argv[optind], "--") != 0) {
    struct passwd *pw;
    pw = getpwnam(argv[optind]);
    if (pw == NULL) {
      char *endptr = NULL;
      wanted_uid = strtoul(argv[optind], &endptr, 10);
      if (argv[optind][0] == '\0' /*empty ID string*/ || *endptr != '\0' /*not completely parsed*/) {
        fprintf(stderr, "Unknown id: %s\n", argv[optind]);
        exit(EXIT_FAILURE);
      }
    } else {
      wanted_uid = pw->pw_uid;
    }
    if (wanted_uid < 0) err("wanted_uid must not be negative");
    optind++;
  }
  
  if (optind < argc && !strcmp(argv[optind], "--")) optind++;
  
  if (setgroups(0, NULL)) err("setgroups() failed");
  int caller_uid = getuid();
  int own_app_uid = get_own_app_uid();
  
  int retrying_after_intent = 0;
retry:
  switch (get_uid_state(caller_uid)) {
    case STATE_ALLOWED: {
      // permission granted - vulns from here on won't have any impact
      if (setresgid(wanted_uid, wanted_uid, wanted_uid) != 0) err("can't change gid!");
      if (setresuid(wanted_uid, wanted_uid, wanted_uid) != 0) err("can't change uid!");
      
      if (!preserve_env) {
        struct passwd *pw = getpwuid(wanted_uid);
        if (pw) {
          setenv("HOME", pw->pw_dir, 1);
          setenv("SHELL", shell, 1);
          setenv("USER", pw->pw_name, 1);
          setenv("LOGNAME", pw->pw_name, 1);
        }
      }
      
      char **new_argv = calloc(sizeof(*new_argv), (3/*sh -c x*/+1+argc-optind));
      int new_argc = 0;
      if (new_argv == NULL) err("alloc fail");
      new_argv[new_argc++] = shell;
      if (command != NULL) {
        new_argv[new_argc++] = "-c";
        new_argv[new_argc++] = command;
      }
      for (int i=optind; i<argc; i++) {
        new_argv[new_argc++] = argv[i];
      }
      
      new_argv[new_argc] = NULL;
      execv(shell, new_argv);
      err("execv() returned (e.g. it failed)");
      break;
    }
    case STATE_DENIED: {
      err("gtfo");
      break;
    }
    case STATE_UNDEFINED: {
      // no setting present. tell the app to ask the user for one, then wait for a signal.
      int child_pid = fork();
      if (child_pid == -1) err("fork() fail");
      if (child_pid == 0) {
        // prevent half-alive processes
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() == 1) exit(1);
        // make target practice target shootable
        if (setresgid(own_app_uid, own_app_uid, own_app_uid) != 0) err("can't change gid!");
        if (setresuid(own_app_uid, own_app_uid, own_app_uid) != 0) err("can't change uid!");
        send_request_intent(caller_uid, getpid()); // mrproper's our environment
        pause();
        exit(0);
      }
      waitpid(child_pid, NULL, 0);
      goto retry;
    }
  }
  
  return 42; // should never get here
}
