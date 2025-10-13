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

    return 0;
}
