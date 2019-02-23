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

#include "detector_headers.h"
#include "module_detect.h"
#include "module_def.h"
#include "rootkit_names.h"

extern linker_file_list_t linker_files;
extern linker_file_t linker_kernel_file;
extern struct sx kld_sx;
extern int next_file_id;

typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;

static const char *names[NUM_NAMES] = NAMES;

// Case insensitive substring search
static char *strstr_case(const char *big, const char *small) {
    char temp[MAXPATHLEN + 1];
    temp[MAXPATHLEN] = '\0';
    for (int i = 0; i < MAXPATHLEN; ++i) {
        if (big[i] == '\0') {
            temp[i] = '\0';
            break;
        } else if (big[i] >= 'A' && big[i] <= 'Z') {
            temp[i] = big[i] + ('a' - 'A'); 
        } else {
            temp[i] = big[i];
        }
    }

    return strstr(temp, small);
}

int module_detect(void) {
    unsigned int link_count = 0, file_id_count = 0, refs = 0, ref_count = 1, module_count = 0, mod_id_count = 0;
    struct linker_file *l;
    struct module *m;
    char mod_found = 0;
    char found_name[MAXPATHLEN + 1];
    found_name[MAXPATHLEN] = '\0';
    uprintf("[MODULE_CHECK] Starting...\n");

    uprintf("Checking modules...\n");

    // Acquire lock
    mtx_lock(&Giant);
    sx_xlock(&kld_sx);
    sx_xlock(&modules_sx);

    // Check linker files
    TAILQ_FOREACH(l, &linker_files, link) {
        // Count linker files and refs of non-kernel linker files
        link_count++; 
        if (l->id != 1) {
		ref_count += l->refs +1;
	}

        // Check if linker file name is suspicious
        for (int i = 0; i < NUM_NAMES && !mod_found; ++i) {
            if (strstr_case(l->filename, names[i])) {
                mod_found = 1;
                strncpy(found_name, l->filename, MAXPATHLEN);
            }
        }
    }

    // Get next linker file id and number of kernel refs
    file_id_count = next_file_id;
    refs = linker_kernel_file->refs; 

    // Check modules
    TAILQ_FOREACH(m, &modules, link) {
        // Count modules
        module_count++; 
        
        // Check if module name is suspicious
        for (int i = 0; i < NUM_NAMES && !mod_found; ++i) {
            if (strstr_case(m->name, names[i])) {
                mod_found = 1;
                strncpy(found_name, m->name, MAXPATHLEN);
            }
        }
    }

    // Get next module id
    mod_id_count = nextid; 

    // Release locks
    sx_xunlock(&modules_sx);
    sx_xunlock(&kld_sx);
    mtx_unlock(&Giant);

    uprintf("=> links: %u  next_file_id: %u  refs: %u  ref_count: %u  modules: %u  next_mod_id: %d\n",
            link_count, file_id_count, refs, ref_count, module_count, mod_id_count);
    
    if (mod_found) {
        uprintf("=> found module: %s\n", found_name);
    }

    // Only checking reference counts and names is reliable
    int res = (refs != ref_count) || mod_found;

    if (res) {
        uprintf("=> module check failed\n");
    } else {
        uprintf("=> module check passed\n");
    }
    uprintf("[MODULE_CHECK] Finished\n");

    return res;
}
