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
    
    detector_vm_alloc.c 
    Allocate userspace memory via vm_map

*/


#include "detector_vm_alloc.h"

// Allocate a page from process vm
vm_offset_t alloc_vm(struct vmspace *vm) {
    // Get base of process vm
    vm_offset_t base = round_page((vm_offset_t) vm->vm_daddr);
    vm_offset_t addr = base + ctob(vm->vm_dsize);

    // Allocate free page in vm
    int ret = vm_map_find(&vm->vm_map, NULL, 0, &addr, PAGE_SIZE, 0, FALSE, VM_PROT_ALL, VM_PROT_ALL, 0);
    if (ret != KERN_SUCCESS) return 0;
    vm->vm_dsize += btoc(PAGE_SIZE);

    return addr;
}

// Free an allocated vm page
void free_vm(struct vmspace *vm, vm_offset_t addr) {
    vm_map_remove(&vm->vm_map, addr, addr + PAGE_SIZE);
    vm->vm_dsize -= btoc(PAGE_SIZE);
}
