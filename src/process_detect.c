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

    process_detect.c
    Counts various operating system process related
    statistics in a few ways and compares them for inconsistencies

*/

#include "detector_headers.h"
#include "process_detect.h"
#include "dlist.h"

#define MAX_PID 100000

static void child_seen_copy(data_ptr_t old, data_ptr_t new) {
    pid_t *old_p = (pid_t *)old;
    pid_t *new_p = (pid_t *)new;
    *new_p = *old_p;
}

static char child_seen_eq(data_ptr_t d1, data_ptr_t d2) {
    pid_t *p1 = (pid_t *)d1;
    pid_t *p2 = (pid_t *)d2;
    return *p1 == *p2;
}

static char unique_insert(dlist_t l, pid_t p) {
    pid_t temp;

    if (!dlist_find(l, &p, &child_seen_eq, &child_seen_copy, &temp)) {
        return dlist_insert(l, &p, &child_seen_copy);
    }

    return 1;
}

static int check_process_count(void) {
    unsigned int list_c = 0, zomb_c = 0, nproc_c = 0, pgrp_c = 0;
    struct proc *p, *child;
    struct pgrp *pg;
    pid_t temp;
    
    uprintf("Checking process counts...\n");

    // Create pid seen lists
    char child_c_failed = 0;
    dlist_t child_seen = dlist_create(sizeof(pid_t));
    if (child_seen == NULL) {
        uprintf("=> failed to allocate child list\n");
        child_c_failed = 1;
    }

    char hash_c_failed = 0;
    dlist_t hash_seen = dlist_create(sizeof(pid_t));
    if (hash_seen == NULL) {
        uprintf("=> failed to allocate hash list\n");
        hash_c_failed = 1;
    }

    char member_c_failed = 0;
    dlist_t member_seen = dlist_create(sizeof(pid_t));
    if (member_seen == NULL) {
        uprintf("=> failed to allocate member list\n");
        member_c_failed = 1;
    }

    // session and pgrp seen lists are either both created, or both NULL
    char pgrp_c_failed = 0;
    dlist_t session_seen = NULL;
    dlist_t pgrp_seen = dlist_create(sizeof(pid_t));
    if (pgrp_seen == NULL) {
        uprintf("=> failed to allocate pgrp list\n");
        pgrp_c_failed = 1;
    } else {
        session_seen = dlist_create(sizeof(pid_t));
        if (session_seen == NULL) {
            uprintf("=> failed to allocate session list\n");
            pgrp_c_failed = 1;
            dlist_destroy(pgrp_seen);
            pgrp_seen = NULL;
        }
    }

    // Lock process tree, list and all processes
    sx_xlock(&proctree_lock);
    sx_xlock(&allproc_lock);
    LIST_FOREACH(p, &allproc, p_list) {
        PROC_LOCK(p);
    }

    // Count the number of processes in allproc and total number of processes in all children lists
    LIST_FOREACH(p, &allproc, p_list) {
        list_c++;

        if (!child_c_failed) {
            child_c_failed = !(unique_insert(child_seen, p->p_pid));
            if (child_c_failed) {
                continue; 
            }

            LIST_FOREACH(child, &p->p_children, p_list) {
                child_c_failed = !(unique_insert(child_seen, child->p_pid));
                if (child_c_failed) {
                    break;
                }
            }
        }
    }

    // Count number of zombies
    LIST_FOREACH(p, &zombproc, p_list) {
        zomb_c++;
    }

    // Iterate through pid and pgrp hash tables
    for (int i = 0; i < MAX_PID && (!hash_c_failed || !member_c_failed || !pgrp_c_failed); ++i) {
        // Count number of processes in pid hash table
        if (!hash_c_failed) {
            LIST_FOREACH(p, PIDHASH(i), p_hash) {
                hash_c_failed = !(unique_insert(hash_seen, p->p_pid));
                if (hash_c_failed) {
                    break; 
                }
            }
        }

        if (!member_c_failed || !pgrp_c_failed) {
            LIST_FOREACH(pg, PGRPHASH(i), pg_hash) {
                // Count total number of processes in all process groups
                if (!member_c_failed) {
                    LIST_FOREACH(p, &pg->pg_members, p_pglist) {
                        member_c_failed = !(unique_insert(member_seen, p->p_pid)); 
                        if (member_c_failed) {
                            break;
                        }
                    }
                }

                // Count total number of process groups in hash and session counts
                if (!pgrp_c_failed) {
                    pgrp_c_failed = !(unique_insert(pgrp_seen, pg->pg_id));
                    if (!pgrp_c_failed && 
                        !dlist_find(session_seen, &pg->pg_session->s_sid, 
                                    &child_seen_eq, &child_seen_copy, &temp)) {
                        pgrp_c_failed = !(unique_insert(session_seen, pg->pg_session->s_sid));
                        if (!pgrp_c_failed) {
                            pgrp_c += pg->pg_session->s_count;
                        }
                    }
                }
            }
        }
    }

    // Get nproc
    nproc_c = nprocs;

    // Release locks
    LIST_FOREACH(p, &allproc, p_list) {
        PROC_UNLOCK(p);
    }
    sx_xunlock(&allproc_lock);
    sx_xunlock(&proctree_lock);

    uprintf("=> allproc: %u  zomb: %u  nproc: %u", list_c, zomb_c, nproc_c);

    // Compare counts
    int res = (list_c != nproc_c);

    if (child_seen != NULL) {
        if (!child_c_failed) {
            uprintf("  child count: %u", dlist_size(child_seen));
            res = res || (list_c != dlist_size(child_seen));
        }
        dlist_destroy(child_seen);
    }

    if (hash_seen != NULL) {
        if (!hash_c_failed) {
            uprintf("  hash count: %u", dlist_size(hash_seen));
            res = res || (list_c != dlist_size(hash_seen));
        }
        dlist_destroy(hash_seen);
    }

    if (member_seen != NULL) {
        if (!member_c_failed) {
            uprintf("  pgrp member count: %u", dlist_size(member_seen));
            res = res || (list_c != dlist_size(member_seen));
        }
        dlist_destroy(member_seen);
    }

    if (pgrp_seen != NULL) {
        if (!pgrp_c_failed) {
            uprintf("  pgrp count: %u  session pgrp count %u", dlist_size(pgrp_seen), pgrp_c);
            res = res || (dlist_size(pgrp_seen) != pgrp_c);
        }
        dlist_destroy(pgrp_seen);
        dlist_destroy(session_seen);
    }
    
    uprintf("\n");

    if (res) {
        uprintf("=> count checking failed\n");
    } else {
        uprintf("=> count checking passed\n");
    }

    return res;
}

static int check_uids(void) {
    int res = 0;
    struct proc *p;
    uid_t ruid, euid;
    pid_t pd;
    char p_name[MAXCOMLEN + 1];

    
    uprintf("Checking process creds...\n");

    // Lock process tree, list and all processes
    sx_xlock(&proctree_lock);
    sx_xlock(&allproc_lock);
    LIST_FOREACH(p, &allproc, p_list) {
        PROC_LOCK(p);
    }
    
    LIST_FOREACH(p, &allproc, p_list) {
        euid = p->p_ucred->cr_uid;
        ruid = p->p_ucred->cr_ruid;
        if (euid == 0 && ruid != 0 && !strcmp(p->p_comm, "sh")) {
            pd = p->p_pid;
            strncpy(p_name, p->p_comm, MAXCOMLEN);
            res = 1;
            break;
        }
    }

    // Release locks
    LIST_FOREACH(p, &allproc, p_list) {
        PROC_UNLOCK(p);
    }
    sx_xunlock(&allproc_lock);
    sx_xunlock(&proctree_lock);

    if (res) {
        uprintf("=> uid checking failed\n");
        uprintf("=> pid: %d  com: %s  euid: %d  ruid: %d\n", pd, p_name, euid, ruid);
    } else {
        uprintf("=> uid checking passed\n");
    }

    return res;
}

int process_detect(void) {
    int res = 0;
    uprintf("[PROCESS_CHECK] Starting\n");

    res = res || check_process_count();
    res = res || check_uids();

    uprintf("[PROCESS_CHECK] Finished\n");
    return res; 
}
