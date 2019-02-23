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
  
    Executes syscall(argv[1]) where argv is a number
    Inteded use of this program is for ./detect
     where a new syscall is loaded in and is called by number

*/

#include <stdlib.h>
#include <unistd.h>

int main(int argc, char * argv[]) {
    return syscall(atoi(argv[1]));
}
