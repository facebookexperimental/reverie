/* SPDX-License-Identifier: GPL-2.0 */

#ifndef HLIST_H_
#define HLIST_H_

#include <stdint.h>

#include "kernel.h"

/** Double linked lists with a single pointer list head */
struct hlist_head {
  struct hlist_node *first;
};

/** Linked list node */
struct hlist_node {
  struct hlist_node *next, **pprev;
};

#define HLIST_HEAD_INIT                                                        \
  { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {.first = NULL}
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

static inline void INIT_HLIST_NODE(struct hlist_node *h) {
  h->next = NULL;
  h->pprev = NULL;
}

static inline bool hlist_unhashed(const struct hlist_node *h) {
  return !h->pprev;
}

/**
 * Tests whether a list is empty.
 *
 * @param head list to test
 */
static inline bool hlist_empty(const struct hlist_head *h) { return !h->first; }

/**
 * Delete a list entry.
 */
static inline void __hlist_del(struct hlist_node *n) {
  struct hlist_node *next = n->next;
  struct hlist_node **pprev = n->pprev;
  *pprev = next;
  if (next)
    next->pprev = pprev;
}

/**
 * Deletes entry from list.
 *
 * Note that empty list on entry does not return true after this,
 * the entry is in an undefined state.
 *
 * @param entry element to delete from the list
 */
static inline void hlist_del(struct hlist_node *n) {
  __hlist_del(n);
  n->next = (void *)0;
  n->pprev = (void *)0;
}

/**
 * Deletes entry from list and reinitialize it.
 *
 * @param entry element to delete from the list
 */
static inline void hlist_del_init(struct hlist_node *n) {
  if (!hlist_unhashed(n)) {
    __hlist_del(n);
    INIT_HLIST_NODE(n);
  }
}

/**
 * Add a new entry.
 *
 * Insert a new entry after the specified head.
 *
 * @param new new entry to be added
 * @param head list head to add it after
 */
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h) {
  struct hlist_node *first = h->first;
  n->next = first;
  if (first)
    first->pprev = &n->next;
  h->first = n;
  n->pprev = &h->first;
}

/**
 * Add a new entry.
 *
 * Insert a new entry before the specified entry.
 *
 * @param new new entry to be added
 * @param head entry to add it before
 */
static inline void hlist_add_before(struct hlist_node *n,
                                    struct hlist_node *next) {
  n->pprev = next->pprev;
  n->next = next;
  next->pprev = &n->next;
  *(n->pprev) = n;
}

/**
 * Add a new entry.
 *
 * Insert a new entry after the specified entry.
 *
 * @param n new entry to be added
 * @param next entry to add it after
 */
static inline void hlist_add_after(struct hlist_node *n,
                                   struct hlist_node *next) {
  next->next = n->next;
  n->next = next;
  next->pprev = &n->next;

  if (next->next)
    next->next->pprev = &next->next;
}

/**
 * Move a list from one list head to another.
 *
 * @param list entry to move
 * @param head head that will precede our entry
 */
static inline void hlist_move_list(struct hlist_head *old,
                                   struct hlist_head *new) {
  new->first = old->first;
  if (new->first)
    new->first->pprev = &new->first;
  old->first = NULL;
}

/**
 * Get the struct for this entry.
 *
 * @param ptr struct list head pointer
 * @param type type of the struct this is embedded in
 * @param member name of the list struct within the struct
 */
#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_entry_safe(ptr, type, member)                                    \
  ({                                                                           \
    typeof(ptr) ____ptr = (ptr);                                               \
    ____ptr ? hlist_entry(____ptr, type, member) : NULL;                       \
  })

/**
 * Get the first element from a list.
 *
 * @param ptr list head to take the element from
 * @param type type of the struct this is embedded in
 * @param member name of the list struct within the struct
 */
#define hlist_first_entry(head, type, member)                                  \
  list_entry((ptr)->first, type, member)

/**
 * Get the first element from a list.
 *
 * @param ptr list head to take the element from
 * @param type type of the struct this is embedded in
 * @param member name of the list struct within the struct
 */
#define hlist_next_entry(node, type, member)                                   \
  list_entry((node)->member.next, type, member)

/**
 * Iterate over a list.
 *
 * @param pos struct list head to use as a loop counter
 * @param head head for your list
 */
#define hlist_for_each(pos, head)                                              \
  for (pos = (head)->first; pos; pos = pos->next)

/**
 * Iterate over a list safe against removal of list entry.
 *
 * @param pos struct list head to use as a loop counter
 * @param n another struct list head to use as temporary storage
 * @param head head for your list
 */
#define hlist_for_each_safe(pos, n, head)                                      \
  for (pos = (head)->first; pos && ({                                          \
                              n = pos->next;                                   \
                              1;                                               \
                            });                                                \
       pos = n)

/**
 * Iterate over list of given type.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos node pointer to use as a loop cursor
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define hlist_for_each_entry(tpos, pos, head, member)                          \
  for (pos = (head)->first; pos && ({                                          \
                              tpos = hlist_entry(pos, typeof(*tpos), member);  \
                              1;                                               \
                            });                                                \
       pos = pos->next)

/**
 * Iterate over list of given type continuing after current point.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos node pointer to use as a loop cursor
 * @param member name of the list structure within the struct
 */
#define hlist_for_each_entry_continue(tpos, pos, member)                       \
  for (pos = (pos)->next; pos && ({                                            \
                            tpos = hlist_entry(pos, typeof(*tpos), member);    \
                            1;                                                 \
                          });                                                  \
       pos = pos->next)

/**
 * Iterate over list of given type continuing from current point.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos node pointer to use as a loop cursor
 * @param member name of the list structure within the struct
 */
#define hlist_for_each_entry_from(tpos, pos, member)                           \
  for (; pos && ({                                                             \
           tpos = hlist_entry(pos, typeof(*tpos), member);                     \
           1;                                                                  \
         });                                                                   \
       pos = pos->next)

/**
 * Iterate over list of given type safe against removal of list entry.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos node pointer to use as a loop cursor
 * @param n another type pointer to use as temporary storage
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define hlist_for_each_entry_safe(tpos, pos, n, head, member)                  \
  for (pos = (head)->first; pos && ({                                          \
                              n = pos->next;                                   \
                              1;                                               \
                            }) &&                                              \
                            ({                                                 \
                              tpos = hlist_entry(pos, typeof(*tpos), member);  \
                              1;                                               \
                            });                                                \
       pos = n)

#endif /* HLIST_H_ */
