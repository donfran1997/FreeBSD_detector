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


    boot-detect.c

    Searches files containing items loaded at boot time for Rootkits
    Fairly "dumb", currently searches these items and checks their name
    for anything that "seems" malicious

*/

#include "detector_headers.h"
#include "boot_detect.h"
#include "rootkit_names.h"
#include "detector_vm_alloc.h"

#define BUFF_LEN 1024

// String of possible rootkit names
static const char *names[NUM_NAMES] = NAMES;

// Open file with sys_open
static int open_file(struct thread *td, const char *path) {
    // Allocate memory for file path and arg struct
    vm_offset_t addr = alloc_vm(td->td_proc->p_vmspace);
    if (addr == 0) {
        uprintf("=> failed to allocate vm memory for %s\n", path);
        return -1;
    }

    // Copy file path to user memory
    copyout(path, (char *)addr, strlen(path) + 1);

    // Setup arg struct
    struct open_args open_kargs;
    open_kargs.path = (char *)addr;
    open_kargs.flags = O_RDONLY;
    
    // Copy args to user memory and do call
    struct open_args *open_uargs = (struct open_args *)((char *)addr + strlen(path) + 1);
    copyout(&open_kargs, open_uargs, sizeof(struct open_args));
    int err = sys_open(td, open_uargs);
    
    free_vm(td->td_proc->p_vmspace, addr);
    
    if (err) {
        uprintf("=> failed to open %s\n", path);
        return -1;
    } else {
        uprintf("=> opened %s on %d\n", path, td->td_retval[0]);
        return td->td_retval[0];
    }
}

// Close file with sys_close
static void close_file(struct thread *td, int fd) {
    // Allocate memory for arg struct
    vm_offset_t addr = alloc_vm(td->td_proc->p_vmspace);
    if (addr == 0) {
        uprintf("=> failed to close %d\n", fd);
        return;
    }

    // Setup args
    struct close_args close_kargs;
    close_kargs.fd = fd;

    // Copy out and call
    struct close_args *close_uargs = (struct close_args *)addr;
    copyout(&close_kargs, close_uargs, sizeof(struct close_args));
    sys_close(td, close_uargs);

    // Free memory
    free_vm(td->td_proc->p_vmspace, addr);
}

// Read a line from file fd into c_buf (user memory) using read_uargs (user memory) to make read call
static char *read_line(struct thread *td, struct read_args *read_uargs, char *c_buf, int fd) {
    int read_count = 0, buff_len = BUFF_LEN;
    char *temp;

    // Allocate initial buffer for line
    char *line_buf = malloc(buff_len, M_TEMP, M_NOWAIT); 
    if (!line_buf) {
        uprintf("=> failed to allocate line buffer\n");
        return NULL;
    }
    
    while (1) {
        // Do read
        int err = sys_read(td, read_uargs);
        if (err) {
            uprintf("=> failed to read from file\n");
            free(line_buf, M_TEMP);
            return NULL;
        } else if (td->td_retval[0] == 0) {
            // EOF, return empty line string
            line_buf[read_count] = '\0';
            return line_buf;
        }

        // Copy read character into kernel memory
        char c_kbuf;
        copyin(c_buf, &c_kbuf, sizeof(char)); 

        if (c_kbuf == '\n') {
            // End of line, stop reading
            line_buf[read_count] = '\0';
            break;
        } else if (c_kbuf >= 'A' && c_kbuf <= 'Z') {
            // Convert uppercase characters to lowercase
            line_buf[read_count] = c_kbuf + ('a' - 'A');
        } else {
            // Otherwise, copy unchanged
            line_buf[read_count] = c_kbuf;
        }

        read_count++;
        if (read_count == buff_len) {
            // Line buffer filled, reallocate a new buffer
            temp = malloc(buff_len * 2, M_TEMP, M_NOWAIT);
            if (!temp) {
                uprintf("=> failed to reallocate line buffer\n");
                free(line_buf, M_TEMP);
                return NULL;
            }

            strncpy(temp, line_buf, BUFF_LEN);
            free(line_buf, M_TEMP);
            line_buf = temp;
            buff_len *= 2;
        }
    }

    return line_buf;
}

// Check if suspected rootkit module name occurs in the file
static int check_file(struct thread *td, int fd) {
    char found = 0;
    
    // Allocate memory for character buffer and arg struct
    vm_offset_t addr = alloc_vm(td->td_proc->p_vmspace);
    if (addr == 0) {
        uprintf("=> failed to allocate vm memory for checking %d\n", fd);
        return 0;
    }


    // Setup read args 
    struct read_args read_kargs;
    read_kargs.fd = fd;
    read_kargs.buf = (char *)addr;
    read_kargs.nbyte = sizeof(char);

    // Copy out args to user memory
    struct read_args *read_uargs = (struct read_args *)((char *)addr + sizeof(char));
    copyout(&read_kargs, read_uargs, sizeof(struct read_args));
    
    // Read each line in file
    char *line = read_line(td, read_uargs, (char *)addr, fd);
    while (line != NULL) {
        if (line[0] == '\0') {
            // EOF, stop checking
            free(line, M_TEMP);
            break;
        }

        // Check if a suspected module name is a substring of the line
        for (int i = 0; i < NUM_NAMES; ++i) {
            if (strstr(line, names[i])) {
                uprintf("=> found line %s\n", line);
                found = 1; 
                break;
            }
        }

        // Free the buffer and read next line
        free(line, M_TEMP);
        if (found) break;
        line = read_line(td, read_uargs, (char *)addr, fd);
    }
    
    // Free allocated memory
    free_vm(td->td_proc->p_vmspace, addr);
    return found;
}

int boot_detect(struct thread *td) {
    int res = 0;
    uprintf("[BOOT_CHECK] Checking for boot modules...\n");

    // Check if /etc/crontab, /var/cron/tabs/root, or /boot/loader.conf contain rootkit modules
    int cron_fd = open_file(td, "/etc/crontab");
    if (cron_fd != -1) {
        if (check_file(td, cron_fd)) {
            uprintf("[BOOT_CHECK] module found in /etc/crontab\n");
            res = 1;
        }

        close_file(td, cron_fd);
    }

    int cron_root_fd = open_file(td, "/var/cron/tabs/root");
    if (cron_root_fd != -1) {
        if (check_file(td, cron_root_fd)) {
            uprintf("[BOOT_CHECK] module found in /var/cron/tabs/root\n");
            res = 1;
        }

        close_file(td, cron_root_fd);
    }

    int boot_fd = open_file(td, "/boot/loader.conf");
    if (boot_fd != -1) {
        if (check_file(td, boot_fd)) {
            uprintf("[BOOT_CHECK] module found in /boot/loader.conf\n");
            res = 1;
        }

        close_file(td, boot_fd);
    }

    if (res) {
        uprintf("[BOOT_CHECK_FOUND] boot persistance check failed\n");
    } else {
        uprintf("[BOOT_CHECK] boot persistance check passed\n");
    }
    uprintf("[BOOT_CHECK] Finished.\n");

    return res;
}
