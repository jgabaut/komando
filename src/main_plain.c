#include <stdio.h>
#define KMD_IMPLEMENTATION
#include "komando.h"

int main(int argc, char** argv) {
    const char* args[] = {
        "echo",
        "foo",
        NULL,
    };

    Komando cmd = new_shell_command(2, args);
    bool res = run_command_sync(cmd);
    printf("Res: {%s}\n", res ? "ok" : "fail");
    free_command(&cmd);

#ifndef _WIN32
    Komando foo_cmd = new_command(2, args);
#else
    const char* foo_args[] = {
        "cmd.exe",
        "/C",
        "echo foo",
        NULL,
    };
    Komando foo_cmd = new_command(3, foo_args);
#endif // _WIN32

    res = run_command_sync(foo_cmd);
    printf("Res: {%s}\n", res ? "ok" : "fail");
    free_command(&foo_cmd);

    return 0;
}
