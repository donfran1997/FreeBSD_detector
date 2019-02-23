/*
 * COMP6447 Rootkit Detector, 2018s2
 *
 * dlist.h
 * Linked list for detector.
 *
 * 
 * 
 * 
 * 
 */

#ifndef _DLIST_H_
#define _DLIST_H_

typedef struct dlist_head * dlist_t;  // List abstraction.
typedef void * data_ptr_t;            // Pointer to data objects.

typedef void (*data_copy_f)(data_ptr_t old_data, data_ptr_t new_data); // Implements copying of old_data into new_data.
typedef char (*data_equal_f)(data_ptr_t d1, data_ptr_t d2);            // Returns 0 if d1 != d2, non-zero otherwise.

/*
 * Create a new list.
 *      data_size: Size in bytes of data stored by the list.
 *
 * Returns a list abstraction on success, NULL on failure.
 */
dlist_t dlist_create(size_t data_size);

/*
 * Insert data into a list.
 *      list:    Abstraction of list to insert into.
 *      data:    Pointer to data object to be stored.
 *      copy_fn: Function that uses the passed data to initialise the stored data object.
 *
 * Returns 1 on success, 0 on failure. 
 */
char dlist_insert(dlist_t list, data_ptr_t data, data_copy_f copy_fn);

/*
 * Get the size of a list.
 *      list: List to query.
 *
 * Returns the size of the list.
 */
uint32_t dlist_size(dlist_t list);

/*
 * Check if a list contains a data object.
 *      list:     List to query.
 *      data:     Pointer to data object to find.
 *      equal_fn: Function used to check for object equality.
 *      copy_fn:  Function used to copy out results.
 *      res:      Pointer to memory that is filled with object if found.
 *
 * Returns 1 on success, 0 on failure.
 */
char dlist_find(dlist_t list, data_ptr_t data, data_equal_f equal_fn, data_copy_f copy_fn, data_ptr_t res);

/*
 * Find and delete an object from the list.
 *      list:     List to delete from.
 *      data:     Pointer to data object to delete.
 *      equal_fn: Function used to check for equality.
 */
void dlist_delete(dlist_t list, data_ptr_t data, data_equal_f equal_fn);

/*
 * Free all memory associated with a list.
 *      list: List to destroy.
 */
void dlist_destroy(dlist_t list);

#endif /* _DLIST_H_ */
