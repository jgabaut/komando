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
#ifdef KMD_HAS_KOLISEO
#include "../koliseo/src/koliseo.h"

#define DARRAY_T char*
#define DARRAY_NAME Komando
#include "../koliseo/templates/darray.h"
#endif // KMD_HAS_KOLISEO
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

#define KMD_MAJOR 0
#define KMD_MINOR 3
#define KMD_PATCH 2

/**
 * Defines current API version number from KLS_MAJOR, KLS_MINOR and KLS_PATCH.
 */
static const int KOMANDO_API_VERSION_INT =
    (KMD_MAJOR * 1000000 + KMD_MINOR * 10000 + KMD_PATCH * 100);
/**< Represents current version with numeric format.*/

/**
 * Defines current API version string.
 */
static const char KOMANDO_API_VERSION_STRING[] = "0.3.2"; /**< Represents current version with MAJOR.MINOR.PATCH format.*/

#ifndef KMD_HAS_KOLISEO
typedef struct Komando {
    char** args;
    size_t argc;
} Komando;
#endif // KMD_HAS_KOLISEO

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
typedef int Kmd_Fd;
#else
typedef HANDLE Kmd_Process;
typedef HANDLE Kmd_Fd;
#define KMD_PROCESS_INVALID NULL
#endif

bool euser_is_root(void);
#ifndef KMD_HAS_KOLISEO
Komando new_command(size_t argc, const char** args);
Komando new_shell_command(size_t argc, const char** args);
void free_command(Komando* c);
Komando cmd_from_strings(const char** strings, size_t tot_strings, bool* success);
#else
Komando new_command(size_t argc, const char** args, Koliseo_Temp* kls_t);
Komando new_shell_command(size_t argc, const char** args, Koliseo_Temp* kls_t);
Komando new_command_kls_t(size_t argc, const char** args, Koliseo_Temp* kls_t);
Komando new_shell_command_kls_t(size_t argc, const char** args, Koliseo_Temp* kls_t);
Komando cmd_from_strings(const char** strings, size_t tot_strings, bool* success, Koliseo_Temp* kls_t);
#endif // KMD_HAS_KOLISEO
Kmd_Process _run_command_async_fd(Komando c, Kmd_Fd* fdin, Kmd_Fd* fdout, Kmd_Fd* fderr, KmdLoc loc);
Kmd_Process _run_command_async_fp(Komando c, FILE* fdin, FILE* fdout, FILE* fderr, KmdLoc loc);
Kmd_Process _run_command_async(Komando c, KmdLoc loc);
#define run_command_async(cmd) _run_command_async((cmd), KMD_HERE)
#define run_command_async_fd(cmd, fdin, fdout, fderr) _run_command_async_fd((cmd), (fdin), (fdout), (fderr), KMD_HERE)
#define run_command_async_fp(cmd, fin, fout, ferr) _run_command_async_fp((cmd), (fin), (fout), (ferr), KMD_HERE)
bool _command_wait(Kmd_Process p, KmdLoc loc);
#define command_wait(p) _command_wait((p), KMD_HERE)
bool _run_command_sync_fd(Komando c, Kmd_Fd* fdin, Kmd_Fd* fdout, Kmd_Fd* fderr, KmdLoc loc);
bool _run_command_sync_fp(Komando c, FILE* fdin, FILE* fdout, FILE* fderr, KmdLoc loc);
bool _run_command_sync(Komando c, KmdLoc loc);
#define run_command_sync(cmd) _run_command_sync((cmd), KMD_HERE)
#define run_command_sync_fd(cmd, fdin, fdout, fderr) _run_command_sync_fd((cmd), (fdin), (fdout), (fderr), KMD_HERE)
#define run_command_sync_fp(cmd, fin, fout, ferr) _run_command_sync_fp((cmd), (fin), (fout), (ferr), KMD_HERE)

#define run_command(cmd) run_command_sync((cmd))
#define run_command_fd(cmd, fdin, fdout, fderr) run_command_sync((cmd), (fdin), (fdout), (fderr))

void kmd_print_stream_to_file(int source, FILE* dest);
int kmd_compare_stream_to_file(int source, const char *filepath);
bool _run_command_checked(Komando c, bool* matched, bool record, const char* stdout_filename, const char* stderr_filename, KmdLoc loc);

#define run_command_checked(c, matched, record, stdout_filename, stderr_filename) _run_command_checked((c), (matched), (record), (stdout_filename), (stderr_filename), KMD_HERE)
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

#ifndef KMD_HAS_KOLISEO
Komando new_command(size_t argc, const char** args) {
    Komando res = {
        .argc = argc+1,
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
    for (size_t i = 2; i < argc+2; i++) {
        free((char*)sh_args[i]);
    }
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

void free_command(Komando* c) {
    assert(c != NULL);
    for (size_t i = 0; i < c->argc -1; i++) {
        free(c->args[i]);
    }
    free(c->args);
}

Komando cmd_from_strings(const char** strings, size_t tot_strings, bool* success)
{
    Komando cmd = new_command(tot_strings, strings);
    *success = true;
    return cmd;
}
#else

Komando new_command(size_t argc, const char** args, Koliseo_Temp* kls_t) {
    return new_command_kls_t(argc, args, kls_t);
}

Komando new_shell_command(size_t argc, const char** args, Koliseo_Temp* kls_t) {
    return new_shell_command_kls_t(argc, args, kls_t);
}

Komando new_command_kls_t(size_t argc, const char** args, Koliseo_Temp* kls_t) {
    assert(kls_t != NULL);
    Komando* res = Komando_init_t(kls_t);
    for (size_t i = 0; i < argc; i++) {
        assert(args[i] != NULL);
        // Komando_push_t(res, (char*)args[i]);
        char* buf = KLS_PUSH_ARR_T(kls_t, char, strlen(args[i])+1);
        memcpy(buf, args[i], strlen(args[i]) +1);
        Komando_push_t(res, buf);
    }
    Komando_push_t(res, NULL);
    return *res;
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

Komando cmd_from_strings(const char** strings, size_t tot_strings, bool* success, Koliseo_Temp* kls_t)
{
    Komando cmd = new_command(tot_strings, strings, kls_t);
    *success = true;
    return cmd;
}
#endif // KMD_HAS_KOLISEO

Kmd_Process _run_command_async_fd(Komando c, Kmd_Fd* fdin, Kmd_Fd* fdout, Kmd_Fd* fderr, KmdLoc loc) {
    if (euser_is_root()) {
        fprintf(stderr, "[ %s:%i at %s() ] %s():    Can't run commands as root.\n", loc.file, loc.line, loc.func, __func__);
        return KMD_PROCESS_INVALID;
    }
#ifndef KMD_HAS_KOLISEO
    // Komando check
    if (c.argc < 1) {
        fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, not enough arguments: {%zu}.\n", loc.file, loc.line, loc.func, __func__, c.argc);
        return KMD_PROCESS_INVALID;
    } else {
        for (size_t i = 0; i < c.argc -1; i++) {
            if (c.args[i] == NULL) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, argument #{%zu} was NULL.\n", loc.file, loc.line, loc.func, __func__, i);
                return KMD_PROCESS_INVALID;
            }
        }
        if (c.args[c.argc-1] != NULL) {
            fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, arguments array is not NULL terminated. #{%zu} was not NULL.\n", loc.file, loc.line, loc.func, __func__, c.argc);
            return KMD_PROCESS_INVALID;
        }
    }
#else
    // Komando check
    if (c.count < 1) {
        fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, not enough arguments: {%zu}.\n", loc.file, loc.line, loc.func, __func__, c.count);
        return KMD_PROCESS_INVALID;
    } else {
        for (size_t i = 0; i < c.count-1; i++) {
            if (c.items[i] == NULL) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, argument #{%zu} was NULL.\n", loc.file, loc.line, loc.func, __func__, i);
                return KMD_PROCESS_INVALID;
            }
        }
        if (c.items[c.count-1] != NULL) {
            fprintf(stderr, "[ %s:%i at %s() ] %s(): Komando malformed, arguments array is not NULL terminated. #{%zu} was not NULL.\n", loc.file, loc.line, loc.func, __func__, c.count);
            return KMD_PROCESS_INVALID;
        }
    }
#endif // KMD_HAS_KOLISEO

    // Run
#ifndef _WIN32
    pid_t child_pid = -1;

    child_pid = fork();

#ifndef KMD_HAS_KOLISEO
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
    if (child_pid < 0) {
        fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not fork for command {%s}.\n", loc.file, loc.line, loc.func, __func__, c.items[0]);
        exit(EXIT_FAILURE);
    } else if (child_pid == 0) {
        if (fdin) {
            if (dup2(*fdin, STDIN_FILENO) < 0) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not dup2 fdin for command {%s}, {%s}\n", loc.file, loc.line, loc.func, __func__, c.items[0], strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
        if (fdout) {
            if (dup2(*fdout, STDOUT_FILENO) < 0) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not dup2 fdout for command {%s}, {%s}\n", loc.file, loc.line, loc.func, __func__, c.items[0], strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
        if (fderr) {
            if (dup2(*fderr, STDERR_FILENO) < 0) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not dup2 fderr for command {%s}, {%s}\n", loc.file, loc.line, loc.func, __func__, c.items[0], strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
        int exec_res = execvp(c.items[0], c.items);
        if (exec_res < 0) {
            fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not exec for command {%s}. {%s}.\n", loc.file, loc.line, loc.func, __func__, c.items[0], strerror(errno));
            exit(EXIT_FAILURE);
        }
        assert(false && "UNREACHABLE");
    }
    return child_pid;
#endif // KMD_HAS_KOLISEO
#else
    size_t total_len = 0;
#ifndef KMD_HAS_KOLISEO
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
#else
    for (size_t i = 0; i < c.count; i++) {
        total_len += strlen(c.items[i]) + 3; // quotes + space
    }
    char* cmdline = malloc(total_len + 1);
    if (!cmdline) return NULL;
    cmdline[0] = '\0';

    for (size_t i = 0; i < c.count; i++) {
        strcat(cmdline, "\"");
        strcat(cmdline, c.items[i]);
        strcat(cmdline, "\"");
        if (i < c.count - 1) strcat(cmdline, " ");
    }
#endif // KMD_HAS_KOLISEO

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    si.hStdError = fderr ? *fderr : GetStdHandle(STD_ERROR_HANDLE);
    si.hStdOutput = fdout ? *fdout : GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdInput = fdin ? *fdin : GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;


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
        TRUE,          // inherit handles
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

Kmd_Process _run_command_async_fp(Komando c, FILE* fin, FILE* fout, FILE* ferr, KmdLoc loc) {
    Kmd_Fd fdin = {0};
    Kmd_Fd fdout = {0};
    Kmd_Fd fderr = {0};
    int in = -1;
    int out = -1;
    int err = -1;
    bool use_fdin = false;
    bool use_fdout = false;
    bool use_fderr = false;
    if (fin) {
        in = fileno(fin);
        if (in >= 0) {
#ifndef _WIN32
            fdin = in;
#else
            fdin = (Kmd_Fd) _get_osfhandle(in);
            if (fdin == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not get HANDLE for fdin.\n", loc.file, loc.line, loc.func, __func__);
                return KMD_PROCESS_INVALID;
            }
#endif // _WIN32
            use_fdin = true;
        }
    }
    if (fout) {
        out = fileno(fout);
        if (out >= 0) {
#ifndef _WIN32
            fdout = out;
#else
            fdout = (Kmd_Fd) _get_osfhandle(out);
            if (fdout == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not get HANDLE for fdout.\n", loc.file, loc.line, loc.func, __func__);
                return KMD_PROCESS_INVALID;
            }
#endif // _WIN32
            use_fdout = true;
        }
    }
    if (ferr) {
        err = fileno(ferr);
        if (err >= 0) {
#ifndef _WIN32
            fderr = err;
#else
            fderr = (Kmd_Fd) _get_osfhandle(err);
            if (fderr == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "[ %s:%i at %s() ] %s(): Could not get HANDLE for fderr.\n", loc.file, loc.line, loc.func, __func__);
                return KMD_PROCESS_INVALID;
            }
#endif // _WIN32
            use_fderr = true;
        }
    }
    return _run_command_async_fd(c,
            use_fdin ? &fdin : NULL,
            use_fdout ? &fdout : NULL,
            use_fderr ? &fderr : NULL,
        loc);
}

Kmd_Process _run_command_async(Komando c, KmdLoc loc) {
    return _run_command_async_fd(c, NULL, NULL, NULL, loc);
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

bool _run_command_sync_fd(Komando c, Kmd_Fd* fdin, Kmd_Fd* fdout, Kmd_Fd* fderr, KmdLoc loc) {
    Kmd_Process p = _run_command_async_fd(c, fdin, fdout, fderr, loc);
    bool res = _command_wait(p, loc);
    return res;
}

bool _run_command_sync_fp(Komando c, FILE* fin, FILE* fout, FILE* ferr, KmdLoc loc) {
    Kmd_Process p = _run_command_async_fp(c, fin, fout, ferr, loc);
    bool res = _command_wait(p, loc);
    return res;
}

bool _run_command_sync(Komando c, KmdLoc loc) {
    return _run_command_sync_fd(c, NULL, NULL, NULL, loc);
}

void kmd_print_stream_to_file(int source, FILE* dest)
{
    if (!dest) return;
    char buffer[256];
    ssize_t count;
    while ((count = read(source, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[count] = '\0';
        fprintf(dest, "%s", buffer);
    }
}

int kmd_compare_stream_to_file(int source, const char *filepath)
{
    if (!filepath) return 0;

    // Open the file for comparison
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("Failed to open file");
        return -1; // error opening file
    }

    // Buffer for reading from both the source and the file
    char source_buffer[256];
    char file_buffer[256];
    ssize_t source_count, file_count;

    // Compare the contents
    while ((source_count = read(source, source_buffer, sizeof(source_buffer))) > 0) {
        file_count = fread(file_buffer, 1, source_count, file);

        if (source_count != file_count || memcmp(source_buffer, file_buffer, source_count) != 0) {
            fclose(file);
            return 0; // contents don't match
        }
    }

    // Check if there are any remaining bytes in the file
    if (fread(file_buffer, 1, sizeof(file_buffer), file) > 0) {
        fclose(file);
        return 0; // the file has more data left
    }

    fclose(file);
    return 1; // contents match
}

bool _run_command_checked(Komando c, bool* matched, bool record, const char* stdout_filename, const char* stderr_filename, KmdLoc loc) {
    FILE* fout = tmpfile();
    if (!fout) {
        fprintf(stderr, "[ %s:%i ] %s(): tmpfile() failed.\n",
            loc.file, loc.line, __func__);
        return -1;
    }
    FILE* ferr = tmpfile();
    if (!ferr) {
        fprintf(stderr, "[ %s:%i ] %s(): tmpfile() failed.\n",
            loc.file, loc.line, __func__);
        fclose(fout);
        return -1;
    }
    bool res = _run_command_sync_fp(c, NULL, fout, ferr, loc);
    rewind(fout);
    int out_fd = fileno(fout);
    int stdout_res = kmd_compare_stream_to_file(out_fd, stdout_filename);
    switch (stdout_res) {
        case 0: {
            *matched = false;
            FILE* stdout_file = fopen(stdout_filename, "rb");
            if (!stdout_file) {
                fprintf(stderr, "Failed opening stdout record at {%s}\n", stdout_filename);
            } else {
                printf("Expected: {\"\n");
                int stdout_record_fd = fileno(stdout_file);
                kmd_print_stream_to_file(stdout_record_fd, stdout);
                printf("\"}\nFound: {\"\n");
                rewind(fout);
                kmd_print_stream_to_file(out_fd, stdout);
                printf("\"}\n");
                if (record) {
                    fclose(stdout_file);
                    FILE* stdout_file = fopen(stdout_filename, "w");
                    rewind(fout);
                    kmd_print_stream_to_file(out_fd, stdout_file);
                    fclose(stdout_file);
                } else {
                    fclose(stdout_file);
                }
            }
        }
        break;
        case 1: { *matched = true; }
        break;
        case -1: {
            *matched = false;
            printf("stdout record {%s} not found\n", stdout_filename);
        }
        break;
        default: {
            printf("unexpected result: {%i}\n", stdout_res);
        }
        break;
    }
    rewind(ferr);
    int err_fd = fileno(ferr);
    int stderr_res = kmd_compare_stream_to_file(err_fd, stderr_filename);
    switch (stderr_res) {
        case 0: {
            *matched = false;
            FILE* stderr_file = fopen(stderr_filename, "rb");
            if (!stderr_file) {
                fprintf(stderr, "Failed opening stderr record at {%s}\n", stderr_filename);
            } else {
                printf("Expected: {\"\n");
                int stderr_record_fd = fileno(stderr_file);
                kmd_print_stream_to_file(stderr_record_fd, stdout);
                printf("\"}\nFound: {\"\n");
                rewind(ferr);
                kmd_print_stream_to_file(err_fd, stdout);
                printf("\"}\n");
                if (record) {
                    fclose(stderr_file);
                    FILE* stderr_file = fopen(stderr_filename, "w");
                    rewind(ferr);
                    kmd_print_stream_to_file(err_fd, stderr_file);
                    fclose(stderr_file);
                } else {
                    fclose(stderr_file);
                }
            }
        }
        break;
        case 1: { *matched = true; }
        break;
        case -1: {
            *matched = false;
            printf("stderr record {%s} not found\n", stderr_filename);
        }
        break;
        default: {
            printf("unexpected result: {%i}\n", stderr_res);
        }
        break;
    }
    fclose(fout);
    fclose(ferr);
    return res; // Returns result of the command
}
#endif // KMD_IMPLEMENTATION
