#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

static int open_hook(struct thread *td, void *syscall_args)
{
    struct open_args *uap;
    uap = (struct open_args *)syscall_args;
    uprintf("myow");
    return(sys_open(td, syscall_args));
}

static int load(struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch(cmd) {
    case MOD_LOAD:
        sysent[SYS_open].sy_call = (sy_call_t *)open_hook;
        break;
    case MOD_UNLOAD:
        sysent[SYS_open].sy_call = (sy_call_t *)sys_open;
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }

    return error;

}
static moduledata_t open_hook_mod = {
    "open_hook",
    load,
    NULL
};

DECLARE_MODULE(open_hook, open_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
