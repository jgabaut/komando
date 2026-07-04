#define KMD_HAS_KOLISEO
#define KMD_IMPLEMENTATION
#include "komando.h"
#include <stdio.h>

int main(int argc, char** argv) {
    const char* args[] = {
        "echo",
        "foo",
        NULL,
    };

    Koliseo* k = kls_new(KLS_DEFAULT_SIZE);
    Koliseo_Temp* kls_t = kls_temp_start(k);

    Komando cmd = new_shell_command(2, args, kls_t);
    bool res = run_command_sync(cmd);
    printf("Res: {%s}\n", res ? "ok" : "fail");

    Komando kmd = new_shell_command_kls_t(2, args, kls_t);
    res = run_command_sync(kmd);
    printf("Res: {%s}\n", res ? "ok" : "fail");

#ifndef _WIN32
    Komando foo_kmd = new_command_kls_t(2, args, kls_t);
#else
    const char* foo_args[] = {
        "cmd.exe",
        "/C",
        "echo foo",
        NULL,
    };
    Komando foo_kmd = new_command_kls_t(3, foo_args, kls_t);
#endif // _WIN32

    res = run_command_sync(foo_kmd);
    printf("Res: {%s}\n", res ? "ok" : "fail");

    kls_temp_end(kls_t);
    kls_free(k);

    return 0;
}
