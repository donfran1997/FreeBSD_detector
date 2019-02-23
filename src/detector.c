/*

###################################################################
#                                                                 #
#   ROOTKIT DETECTOR                                              #
#   UNSW COMP6448 2019tX (01/2019-02/2019)                        #
#                                                                 #
#   The below program has been written by the students            #
#   of the COMP6448 - Security Masterclass course in              #
#   the Jan/Feb of 2019 Summer Term.                              #
#                                                                 #
#   This program draws from student detectors submitted           #
#   in 2018s2 COMP6447 - System and Software Security Assessment  #
#                                                                 #
###################################################################


    detector.c
    The main kernel module of the detector
    Installs a Syscall which runs many of
    the detection methods in kernel space


*/
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

#include "checksum_hook_detect.h"
#include "detector_headers.h"
#include "process_detect.h"
#include "boot_detect.h"
#include "module_detect.h"
static int offset = NO_SYSCALL;

struct new_syscall_args {

};

static int new_syscall(struct thread *td, void *syscall_args)
{
    int ret=0;
    struct new_syscall_args *uap;
    uap = (struct new_syscall_args *) syscall_args;
    uprintf("Hello, I am a syscall"); 
    ret = checksum_hook_detect(offset) || ret;
    ret = process_detect()             || ret;
    ret = boot_detect(td)              || ret;
    ret = module_detect()              || ret;
    td->td_retval[0] = ret;
    return(0);

}

static struct sysent new_syscall_sysent = {
    1,          /* number of arguments */
    new_syscall /* function that implements syscall */
};

static int load(struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch(cmd) {
    case MOD_LOAD:
        uprintf("[MODULE] Module Loaded: Syscall available at %d\n", offset);
        printf("[MODULE] Rootkit Detector: I am here. Syscall loaded at %d\n", offset);
        break;
    case MOD_UNLOAD:
        uprintf("[MODULE] Module Unloaded: Good bye Kernel.\n");
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }

    return error;

}

SYSCALL_MODULE(new_syscall, &offset, &new_syscall_sysent, load, NULL);
