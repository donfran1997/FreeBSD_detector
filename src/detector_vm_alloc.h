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

*/


#ifndef _DETECTOR_VM_ALLOC_H_
#define _DETECTOR_VM_ALLOC_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

vm_offset_t alloc_vm(struct vmspace *vm);
void free_vm(struct vmspace *vm, vm_offset_t addr); 

#endif /* _DETECTOR_VM_ALLOC_H_ */
