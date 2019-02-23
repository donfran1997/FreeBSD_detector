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

    detector_headers.h
    Included files for detector modules
    Bit of an "all comers" approach

*/


#ifndef _DETECTOR_HEADERS_H_
#define _DETECTOR_HEADERS_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>

#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/module.h>

#include <sys/queue.h>
#include <sys/resourcevar.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>

#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>

#include <sys/dirent.h>
#include <sys/malloc.h>
#include <sys/proc.h>

#include <sys/fcntl.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>

#endif /* _DETECTOR_HEADERS_H_ */
