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

# Makefile

#Name of KLD
KMOD=	detector
#List of src
SRCS=	detector.c process_detect.c dlist.c boot_detect.c detector_vm_alloc.c module_detect.c checksum_hook_detect.c

.include <bsd.kmod.mk>

#clean_all: clean
#    -rm -f .depend.*
