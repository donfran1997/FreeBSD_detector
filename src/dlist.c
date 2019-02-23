/*
 * COMP6447 Rootkit Detector, 2018s2
 *
 * dlist.c
 * Linked list implementation.
 *
 * 
 * 
 * 
 * 
 */

#include <sys/types.h>
#include <sys/malloc.h>

#include "dlist.h"

struct dlist_head {
    struct dlist_node *first;
    struct dlist_node *last;
    uint32_t size;
    size_t data_size;
};

struct dlist_node {
    struct dlist_node *next;
    struct dlist_node *prev;
    data_ptr_t data;
};

dlist_t dlist_create(size_t data_size) {
    dlist_t l = malloc(sizeof(struct dlist_head), M_TEMP, M_NOWAIT);
    if (l == NULL) return NULL;

    l->first = NULL;
    l->last = NULL;
    l->size = 0;
    l->data_size = data_size;
    return l;
}

char dlist_insert(dlist_t list, data_ptr_t data, data_copy_f copy_fn) {
    struct dlist_node *n = malloc(sizeof(struct dlist_node), M_TEMP, M_NOWAIT);
    if (n == NULL) return 0;

    data_ptr_t d = malloc(list->data_size, M_TEMP, M_NOWAIT);
    if (d == NULL) {
        free(n, M_TEMP);
        return 0;
    }

    copy_fn(data, d);
    n->data = d;
    n->next = NULL;
    n->prev = NULL;

    if (list->size == 0) {
        list->first = n;
        list->last = n;
    } else {
        list->last->next = n;
        n->prev = list->last;
        list->last = n;
    }

    list->size++;
    return 1;
}

uint32_t dlist_size(dlist_t list) {
    return list->size;
}

static struct dlist_node *_find(dlist_t list, data_ptr_t data, data_equal_f equal_fn) {
    if (list->size == 0) return NULL;

    struct dlist_node *c = list->first;
    while (c != NULL) {
        if (equal_fn(c->data, data)) break;
        c = c->next;
    }

    return c;
}

char dlist_find(dlist_t list, data_ptr_t data, data_equal_f equal_fn, data_copy_f copy_fn, data_ptr_t res) {
    struct dlist_node *c = _find(list, data, equal_fn);
    if (c == NULL) {
        return 0;
    } else {
        copy_fn(data, res);
        return 1;
    }
}
void dlist_delete(dlist_t list, data_ptr_t data, data_equal_f equal_fn) {
    struct dlist_node *c = _find(list, data, equal_fn);
    if (c == NULL) return;

    if (c->next != NULL) c->next->prev = c->prev;
    if (c->prev != NULL) c->prev->next = c->next;
    if (c == list->first) list->first = c->next;
    if (c == list->last) list->last = c->prev;

    free(c->data, M_TEMP);
    free(c, M_TEMP);
    list->size--;
}

void dlist_destroy(dlist_t list) {
    struct dlist_node *c = list->first;
    struct dlist_node *p;

    while (c != NULL) {
        p = c;
        c = c->next;
        free(p->data, M_TEMP);
        free(p, M_TEMP);
    }

    free(list, M_TEMP);
}
