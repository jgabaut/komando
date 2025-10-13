#include <stdio.h>
#define KMD_HAS_KOLISEO
#define KMD_IMPLEMENTATION
#include "komando.h"

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
    kls_temp_end(kls_t);
    kls_free(k);

    return 0;
}
