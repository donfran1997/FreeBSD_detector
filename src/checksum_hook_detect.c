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


    checksum_hook_detect.c
    Attempts to discover inline syscall hooks by summing
     the first 10 instructions at the current sysent[]
     and comparing them to a pre-compiled list of expected
     "checksums"

*/

#define COMPAT_FREEBSD6
#define COMPAT_FREEBSD7
#define COMPAT_FREEBSD10
#define COMPAT_FREEBSD4
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>

#include "checksum_hook_detect.h"
#include "checksum_hook_detect_extras.h"

// our_syscall is a syscall number to 'ignore'
// we don't need to check our owndetector syscall
int checksum_hook_detect(int our_syscall) {
    int bad=0;
    // see checksum_hook_detect_extras.h
    // functions[] is an array of syscalls
    // syscall_ids[] is a corresponding list of syscall nums
    // checksum_algo[] is a corresponding list of expected "checksums"
    for (int counter = 0; functions[counter] != NULL; counter++ ) {
        // Skip our syscall
        if  (counter == our_syscall) continue;
        int sysent_to_check = syscall_ids[counter];

        int checksum = 0;
        // set start_of_function to the top of the system call according to the sysent
        char* start_of_function = (char*) sysent[sysent_to_check].sy_call;
        // Sum the first 10 instructions
        for(int i = 0; i < 10; i++) {
            int instruction = ((int)start_of_function[i] & 0xFF);
            checksum += instruction;
        }
        // Check expected vs calculated
        if (checksum != checksum_algo[sysent_to_check]) {
            uprintf("[HOOK_CHECK_FOUND] Warning syscall %d's start  has checksum %d not %d\n",
                sysent_to_check, checksum, checksum_algo[sysent_to_check]);
            bad = 1;
        }
    }
    return bad;
}


