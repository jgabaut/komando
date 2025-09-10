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
#ifndef CANVIL_COMMAND_H_
#define CANVIL_COMMAND_H_
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
#define KMD_PATCH 0

/**
 * Defines current API version number from KLS_MAJOR, KLS_MINOR and KLS_PATCH.
 */
static const int KOMANDO_API_VERSION_INT =
    (KMD_MAJOR * 1000000 + KMD_MINOR * 10000 + KMD_PATCH * 100);
/**< Represents current version with numeric format.*/

/**
 * Defines current API version string.
 */
static const char KOMANDO_API_VERSION_STRING[] = "0.1.0"; /**< Represents current version with MAJOR.MINOR.PATCH format.*/

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
#endif // CANVIL_COMMAND_H_
