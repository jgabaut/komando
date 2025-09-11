// jgabaut @ github.com/jgabaut
// SPDX-License-Identifier: GPL-3.0-only
/*
    Copyright (C) 2024 jgabaut

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef KOMANDO_H_
#define KOMANDO_H_
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#ifndef _WIN32
#include <sys/wait.h>
#else
#include <windows.h>
#endif
#include <errno.h>
#ifdef KMD_HAS_KOLISEO
#include "../koliseo/src/koliseo.h"
#endif // KMD_HAS_KOLISEO

#define KMD_MAJOR 0
#define KMD_MINOR 1
#define KMD_PATCH 1

/**
 * Defines current API version number from KLS_MAJOR, KLS_MINOR and KLS_PATCH.
 */
static const int KOMANDO_API_VERSION_INT =
    (KMD_MAJOR * 1000000 + KMD_MINOR * 10000 + KMD_PATCH * 100);
/**< Represents current version with numeric format.*/

/**
 * Defines current API version string.
 */
static const char KOMANDO_API_VERSION_STRING[] = "0.1.1"; /**< Represents current version with MAJOR.MINOR.PATCH format.*/

typedef struct Komando {
    char** args;
    size_t argc;
} Komando;

typedef struct KmdLoc {
    const char* file;
    const char* func;
    int line;
} KmdLoc;

#define KMD_HERE (KmdLoc){ \
    .file = __FILE__, \
    .func = __func__, \
    .line = __LINE__, \
}

#ifndef _WIN32
typedef pid_t Kmd_Process;
#define KMD_PROCESS_INVALID -1
#else
typedef HANDLE Kmd_Process;
#define KMD_PROCESS_INVALID NULL
#endif

bool euser_is_root(void);
Komando new_command(size_t argc, const char** args);
Komando new_shell_command(size_t argc, const char** args);
#ifdef KMD_HAS_KOLISEO
Komando new_command_kls_t(size_t argc, const char** args, Koliseo_Temp* kls_t);
Komando new_shell_command_kls_t(size_t argc, const char** args, Koliseo_Temp* kls_t);
#endif // KMD_HAS_KOLISEO
void free_command(Komando* c);
Kmd_Process _run_command_async(Komando c, KmdLoc loc);
#define run_command_async(cmd) _run_command_async((cmd), KMD_HERE)
bool _command_wait(Kmd_Process p, KmdLoc loc);
#define command_wait(p) _command_wait((p), KMD_HERE)
bool _run_command_sync(Komando c, KmdLoc loc);
#define run_command_sync(cmd) _run_command_sync((cmd), KMD_HERE)
Komando cmd_from_strings(const char** strings, size_t tot_strings, bool* success);

#define run_command(cmd) run_command_sync((cmd))
#endif // KOMANDO_H_

#ifdef KMD_IMPLEMENTATION

bool euser_is_root(void) {
#ifndef _WIN32
    uid_t user_id = geteuid(); // Effective user id
    if (user_id == 0) return true;
    return false;
#else
    //TODO: maybe handle this for windows?
    //
    // https://stackoverflow.com/questions/1594746/win32-equivalent-of-getuid
    //
    BOOL is_admin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,0,0,0,0,0,
            &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &is_admin);
        FreeSid(adminGroup);
    }
    return is_admin;
#endif
}

Komando new_command(size_t argc, const char** args) {
    Komando res = {
        .argc = argc,
    };
    res.args = calloc(argc+1, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        assert(args[i] != NULL);
        res.args[i] = strdup(args[i]);
    }
    res.args[argc] = NULL;
    return res;
}

Komando new_shell_command(size_t argc, const char** args)
{
#ifndef _WIN32
    const char** sh_args = calloc(argc+2, sizeof(char*));

    sh_args[0] = "sh";
    sh_args[1] = "-exc";

    for (size_t i = 2; i < argc+2; i++) {
        sh_args[i] = strdup(args[i-2]);
    }
    Komando res = new_command(argc+2, sh_args);

#else
    // WINDOWS: build a single string "echo foo"
    size_t total_len = 0;
    for (size_t i = 0; i < argc; i++) {
        total_len += strlen(args[i]) + 3;
    }

    char* cmdline = malloc(total_len + 1);
    if (!cmdline) return (Komando){0};

    cmdline[0] = '\0';
    for (size_t i = 0; i < argc; i++) {
        const char* arg = args[i];
        bool needs_quotes = (strchr(arg, ' ') != NULL || strchr(arg, '\t') != NULL);

        if (needs_quotes) strcat(cmdline, "\"");
        strcat(cmdline, arg);
        if (needs_quotes) strcat(cmdline, "\"");

        if (i < argc - 1) strcat(cmdline, " ");
    }

    // Build ["cmd.exe", "/C", cmdline]
    const char** sh_args = calloc(4, sizeof(char*));
    sh_args[0] = "cmd.exe";
    sh_args[1] = "/C";
    sh_args[2] = cmdline;
    sh_args[3] = NULL;

    Komando res = new_command(3, sh_args); // Komando made its own copy of sh_args
#endif
    free(sh_args);
    return res;
}

#ifdef KMD_HAS_KOLISEO
Komando new_command_kls_t(size_t argc, const char** args, Koliseo_Temp* kls_t) {
    assert(kls_t != NULL);
    Komando res = {
        .argc = argc,
    };
    res.args = KLS_PUSH_ARR_T(kls_t, char*, argc+1);
    for (size_t i = 0; i < argc; i++) {
        assert(args[i] != NULL);
        res.args[i] = KLS_PUSH_ARR_T(kls_t, char, strlen(args[i])+1);
        memcpy(res.args[i], args[i], strlen(args[i]) +1);
    }
    res.args[argc] = NULL;
    return res;
}

Komando new_shell_command_kls_t(size_t argc, const char** args, Koliseo_Temp* kls_t)
{
    assert(kls_t != NULL);
#ifndef _WIN32
    char** sh_args = KLS_PUSH_ARR_T(kls_t, char*, argc+2);

    sh_args[0] = "sh";
    sh_args[1] = "-exc";

    for (size_t i = 2; i < argc+2; i++) {
        sh_args[i] = KLS_PUSH_ARR_T(kls_t, char, strlen(args[i-2]) +1);
        memcpy(sh_args[i], args[i-2], strlen(args[i-2]) +1);
    }
    Komando res = new_command_kls_t(argc+2, (const char**)sh_args, kls_t);
#else
    size_t total_len = 0;
    for (size_t i = 0; i < argc; i++) {
        total_len += strlen(args[i]) + 3;
    }

    char* cmdline = KLS_PUSH_ARR_T(kls_t, char, total_len + 1);
    cmdline[0] = '\0';
    for (size_t i = 0; i < argc; i++) {
        const char* arg = args[i];
        bool needs_quotes = (strchr(arg, ' ') != NULL || strchr(arg, '\t') != NULL);

        if (needs_quotes) strcat(cmdline, "\"");
        strcat(cmdline, arg);
        if (needs_quotes) strcat(cmdline, "\"");

        if (i < argc - 1) strcat(cmdline, " ");
    }

    char** sh_args = KLS_PUSH_ARR_T(kls_t, char*, 4);
    sh_args[0] = "cmd.exe";
    sh_args[1] = "/C";
    sh_args[2] = cmdline;
    sh_args[3] = NULL;

    Komando res = new_command_kls_t(3, (const char**)sh_args, kls_t);
#endif
    return res;
}
#endif // KMD_HAS_KOLISEO

void free_command(Komando* c) {
    assert(c != NULL);
    for (size_t i = 0; i < c->argc; i++) {
        free(c->args[i]);
    }
    free(c->args);
}

Kmd_Process _run_command_async(Komando c, KmdLoc loc) {
    if (euser_is_root()) {
        fprintf(stderr, "[ %s:%i at %s() ] %s():    Can't run commands as root.\n", loc.file, loc.line, loc.func, __func__);
        return KMD_PROCESS_INVALID;
    }
    // Komando check
    if (c.argc < 1) {
        fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, not enough arguments: {%zu}.\n", loc.file, loc.line, loc.func, __func__, c.argc);
        return KMD_PROCESS_INVALID;
    } else {
        for (size_t i = 0; i < c.argc; i++) {
            if (c.args[i] == NULL) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, argument #{%zu} was NULL.\n", loc.file, loc.line, loc.func, __func__, i);
                return KMD_PROCESS_INVALID;
            }
        }
        if (c.args[c.argc] != NULL) {
            fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, arguments array is not NULL terminated. #{%zu} was not NULL.\n", loc.file, loc.line, loc.func, __func__, c.argc);
            return KMD_PROCESS_INVALID;
        }
    }

    // Run
#ifndef _WIN32
    pid_t child_pid = -1;

    child_pid = fork();

    if (child_pid < 0) {
        fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not fork for command {%s}.\n", loc.file, loc.line, loc.func, __func__, c.args[0]);
        exit(EXIT_FAILURE);
    } else if (child_pid == 0) {

        int exec_res = execvp(c.args[0], c.args);
        if (exec_res < 0) {
            fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not exec for command {%s}. {%s}.\n", loc.file, loc.line, loc.func, __func__, c.args[0], strerror(errno));
            exit(EXIT_FAILURE);
        }
        assert(false && "UNREACHABLE");
    }
    return child_pid;
#else
    size_t total_len = 0;
    for (size_t i = 0; i < c.argc; i++) {
        total_len += strlen(c.args[i]) + 3; // quotes + space
    }
    char* cmdline = malloc(total_len + 1);
    if (!cmdline) return NULL;
    cmdline[0] = '\0';

    for (size_t i = 0; i < c.argc; i++) {
        strcat(cmdline, "\"");
        strcat(cmdline, c.args[i]);
        strcat(cmdline, "\"");
        if (i < c.argc - 1) strcat(cmdline, " ");
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Always use full path to cmd.exe
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    char app[MAX_PATH];
    _snprintf(app, MAX_PATH, "%s\\cmd.exe", sysdir);

    // Build final command line: /C "args..."
    char full_cmdline[32768]; // Windows max
    _snprintf(full_cmdline, sizeof(full_cmdline), "/C %s", cmdline);

    BOOL ok = CreateProcessA(
        app,            // application name
        full_cmdline,   // command line (mutable string)
        NULL, NULL,     // security
        FALSE,          // inherit handles
        0,              // flags
        NULL, NULL,     // env, cwd
        &si, &pi
    );

    free(cmdline);

    if (!ok) {
        fprintf(stderr, "[ %s:%i ] %s(): CreateProcess failed with %lu.\n",
            loc.file, loc.line, __func__, GetLastError());
        return NULL;
    }

    // Close thread handle, keep process handle
    CloseHandle(pi.hThread);
    return pi.hProcess; // return HANDLE
#endif // _WIN32
    //We're not freeing the strings in case the command wants to run again
}

bool _command_wait(Kmd_Process p, KmdLoc loc) {
#ifndef _WIN32
    for (;;) {
        int wstatus = 0;
        if (waitpid(p, &wstatus, 0) < 0) {
            fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not wait on pid {%i}.\n", loc.file, loc.line, loc.func, __func__, p);
            return false;
        }

        if (WIFEXITED(wstatus)) {
            int exit_code = WEXITSTATUS(wstatus);
            if (exit_code != 0) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando exited with code {%i}.\n", loc.file, loc.line, loc.func, __func__, exit_code);
                return false;
            }
            break;
        }

        if (WIFSIGNALED(wstatus)) {
            fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando terminated by {%s}.\n", loc.file, loc.line, loc.func, __func__, strsignal(WTERMSIG(wstatus)));
#ifdef WCOREDUMP
            if (WCOREDUMP(wstatus)) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando produced a core dump.\n", loc.file, loc.line, loc.func, __func__);
            }
#endif // _WCOREDUMP
            return false;
        }
    }

    return true;
#else
    HANDLE hProc = (HANDLE)p;
    WaitForSingleObject(hProc, INFINITE);

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(hProc, &exitCode)) {
        fprintf(stderr, "[ %s:%i ] %s(): GetExitCodeProcess failed.\n",
            loc.file, loc.line, __func__);
        CloseHandle(hProc);
        return false;
    }

    CloseHandle(hProc);
    return (exitCode == 0);
#endif // _WIN32
}

bool _run_command_sync(Komando c, KmdLoc loc) {
    Kmd_Process p = _run_command_async(c, loc);
    bool res = _command_wait(p, loc);
    return res;
}

Komando cmd_from_strings(const char** strings, size_t tot_strings, bool* success)
{
    Komando cmd = new_command(tot_strings, strings);
    *success = true;
    return cmd;
}
#endif // KMD_IMPLEMENTATION
