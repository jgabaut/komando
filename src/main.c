#include <stdio.h>
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

#ifdef KMD_HAS_KOLISEO
    Koliseo* k = kls_new(KLS_DEFAULT_SIZE);
    Koliseo_Temp* kls_t = kls_temp_start(k);
    Komando kmd = new_shell_command_kls_t(2, args, kls_t);
    res = run_command_sync(kmd);
    printf("Res: {%s}\n", res ? "ok" : "fail");
    kls_temp_end(kls_t);
    kls_free(k);
#endif

    return 0;
}
