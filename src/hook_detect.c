/* 
    Incorporating Code from Joseph Kong (2007), and Stephanie Wehner (2001)

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

    hook_detect.c
    Attempts to detect a simple hook via a sysent alteration
    or a "simple inline" hook via instruction changing

*/


#include <kvm.h>
#include <fcntl.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/syscall.h>

#include "syscalltab.h"
#include "hook_detect.h"

int main(int argc, char* argv[]) {
    int retval = 0;
    // for all syscalls, check
    for (int i = 0; i < SYS_MAXSYSCALL; i++) {
        // skip our syscall
        if (i == atoi(argv[1])) continue;
        if (hook_detect(syscalltab[i][1], atoi(syscalltab[i][0])) == 1) retval = 1;
    }
    return retval;
}

int hook_detect(char* syscall_name, int syscall_num) {
    
    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd;
    struct nlist nl[] = { {NULL}, {NULL}, {NULL}, };
    struct sysent call;
    int size = 10;  // size of syscall code to copy
    int length = 3; // number of hex codes to check
    int retval = 0;
    unsigned char bytes[3] = "\x55\x89\xe5"; // push ebp; mov ebp, esp
    unsigned char syscall_code[size];
    unsigned long addr;
    int i;
    
    // Initialize kernel virtual memory access
    kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    if (kd == NULL) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        return 2;
    }

    // Populate nlist
    nl[0].n_name = "sysent";
    nl[1].n_name = syscall_name;

    // Find kernel addresses
    if (kvm_nlist(kd, nl) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        return 2;
    }
    
    // Make sure we have sysent
    if (nl[0].n_value) {
        //printf("%s[] is 0x%x at 0x%lx\n", nl[0].n_name, nl[0].n_type, nl[0].n_value);
    } else {
        fprintf(stderr, "ERROR: %s not found (very weird...)\n", nl[0].n_name);
        return 2;
    }
    
    // Make sure we have syscall info
    if (!nl[1].n_value) {
        fprintf(stderr, "ERROR: %s not found\n", nl[1].n_name);
        return 2;
    }
    
    // Address of sysent[syscall_num];
    addr = nl[0].n_value + syscall_num * sizeof(struct sysent);

    // Copy sysent[syscall_num];
    if (kvm_read(kd, addr, &call, sizeof(struct sysent)) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        return 2;
    }

    // Where does sysent[syscall_num] point to?
    printf("sysent[%d] is at 0x%lx and its sy_call member points to %p\n", syscall_num, addr, call.sy_call);

    // Check if that's correct
    if ((uintptr_t)call.sy_call != nl[1].n_value) {
        printf("[HOOK_CHECK_FOUND]: ALERT! sysent[%d](%s) should point to 0x%lx instead\n", syscall_num, syscall_name, nl[1].n_value);
        retval = 1;
    } else {
        printf("[HOOK_CHECK]: SUCCESS. 0x%x = 0x%lx\n", (uintptr_t)call.sy_call, nl[1].n_value);
    }
    // End of simple hook detect. Moving to inline hook detect

    // Save *size* bytes of syscall code into syscall_code
    if (kvm_read(kd, nl[1].n_value, syscall_code, size) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        return 2;
    }

    // Print Code
    printf("[HOOK_CHECK]: Code for syscall %s\n", syscall_name);
    for (i = 0; i < size; i++) {
        printf("\\x%02x", syscall_code[i]);
    }
    printf("\n");
    // End print Code

    for (i = 0; i < length; i++) {
        if (syscall_code[i] != bytes[i]) {
            retval = 1;
            printf("[HOOK_CHECK_FOUND] Mismatched %s! Current: %x vs Wanted: %x\n", syscall_name, syscall_code[i], bytes[i]);
            break;
        }
    }
    // End of simple inline hook

    if (kvm_close(kd) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        return 2;
    }
     
    return retval;
}
