/*
 * COMP6447 Rootkit Detector, 2018s2
 *
 * module_def.h
 * Kernel module definitions.
 *
 * 
 * 
 * 
 * 
 */

#pragma once

#include "detector_headers.h"

#define DETECTOR_NAME "detector"
#define DETECTOR_FILE "detector.ko"

struct module {
    TAILQ_ENTRY(module) link;
    TAILQ_ENTRY(module) flink;
    struct linker_file *file;
    int refs;
    int id;
    char *name;
    modeventhand_t handler;
    void  *arg;
    modspecific_t data;
};
