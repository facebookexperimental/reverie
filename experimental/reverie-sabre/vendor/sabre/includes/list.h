/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LIST_H_
#define LIST_H_

#include <stdint.h>

#include "kernel.h"

/** Double linked list implementation */
struct list_head {
  struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name)                                                   \
  { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

/**
 * Initialize new linked list entry.
 *
 * @param list new list entry
 */
static inline void INIT_LIST_HEAD(struct list_head *list) {
  list->next = list;
  list->prev = list;
}

/* Insert a new entry between two known consecutive entries. */
static inline void __list_add(struct list_head *new, struct list_head *prev,
                              struct list_head *next) {
  next->prev = new;
  new->next = next;
  new->prev = prev;
  prev->next = new;
}

/* Delete a list entry. */
static inline void __list_del(struct list_head *prev, struct list_head *next) {
  next->prev = prev;
  prev->next = next;
}

/* Join two lists. */
static inline void __list_splice(struct list_head *list, struct list_head *prev,
                                 struct list_head *next) {
  struct list_head *first = list->next;
  struct list_head *last = list->prev;

  first->prev = prev;
  prev->next = first;

  last->next = next;
  next->prev = last;
}

/* Cut list into two. */
static inline void __list_cut_position(struct list_head *list,
                                       struct list_head *head,
                                       struct list_head *entry) {
  struct list_head *new_first = entry->next;
  list->next = head->next;
  list->next->prev = list;
  list->prev = entry;
  entry->next = list;
  head->next = new_first;
  new_first->prev = head;
}

/**
 * Add a new entry.
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 *
 * @param new new entry to be added
 * @param head list head to add it after
 */
static inline void list_add(struct list_head *new, struct list_head *head) {
  __list_add(new, head, head->next);
}

/**
 * Add a new entry.
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 *
 * @param new new entry to be added
 * @param head list head to add it before
 */
static inline void list_add_tail(struct list_head *new,
                                 struct list_head *head) {
  __list_add(new, head->prev, head);
}

/**
 * Deletes entry from list.
 *
 * Note that empty list on entry does not return true after this,
 * the entry is in an undefined state.
 *
 * @param entry element to delete from the list
 */
static inline void list_del(struct list_head *entry) {
  __list_del(entry->prev, entry->next);
  entry->next = (void *)0;
  entry->prev = (void *)0;
}

/**
 * Deletes entry from list and reinitialize it.
 *
 * @param entry element to delete from the list
 */
static inline void list_del_init(struct list_head *entry) {
  __list_del(entry->prev, entry->next);
  INIT_LIST_HEAD(entry);
}

/**
 * Replaces old entry by new one.
 *
 * @param old element to be replaced
 * @param new new element to insert
 */
static inline void list_replace(struct list_head *old, struct list_head *new) {
  new->next = old->next;
  new->next->prev = new;
  new->prev = old->prev;
  new->prev->next = new;
}

/**
 * Replaces entry from list and reinitialize it.
 *
 * @param old element to be replaced
 * @param new new element to insert
 */
static inline void list_replace_init(struct list_head *old,
                                     struct list_head *new) {
  list_replace(old, new);
  INIT_LIST_HEAD(old);
}

/**
 * Delete from one list and add as another's head.
 *
 * @param the list entry to move
 * @param head the head that will precede our entry
 */
static inline void list_move(struct list_head *list, struct list_head *head) {
  __list_del(list->prev, list->next);
  list_add(list, head);
}

/**
 * Delete from one list and add as another's tail.
 *
 * @param the list entry to move
 * @param head the head that will follow our entry
 */
static inline void list_move_tail(struct list_head *list,
                                  struct list_head *head) {
  __list_del(list->prev, list->next);
  list_add_tail(list, head);
}

/**
 * Tests whether an entry is the last entry in list.
 *
 * @param list entry to test
 * @param head head of the list
 */
static inline bool list_is_last(const struct list_head *list,
                                const struct list_head *head) {
  return list->next == head;
}

/**
 * Tests whether a list is empty.
 *
 * @param head The list to test.
 */
static inline bool list_empty(const struct list_head *head) {
  return head->next == head;
}

/**
 * Tests whether a list is empty and not being modified.
 *
 * @param head the list to test
 */
static inline bool list_empty_careful(const struct list_head *head) {
  struct list_head *next = head->next;
  return (next == head) && (next == head->prev);
}

/**
 * Rotate the list to the left.
 *
 * @param head the head of the list
 */
static inline void list_rotate_left(struct list_head *head) {
  if (!list_empty(head)) {
    struct list_head *first = head->next;
    list_move_tail(first, head);
  }
}

/**
 * Tests whether a list has just one entry.
 * @param head the list to test
 */
static inline bool list_is_singular(const struct list_head *head) {
  return !list_empty(head) && (head->next == head->prev);
}

/**
 * Count the length of the list.
 *
 * @param head list to test
 * @return list length
 */
static inline size_t list_length(struct list_head *head) {
  struct list_head *pos;
  size_t length = 0;
  for (pos = head->next; pos != head; pos = pos->next)
    ++length;
  return length;
}

/**
 * Cut a list into two.
 *
 * This helper moves the initial part of @p head, up to and including @p
 * entry, from @p head to @p list. You should pass on @p entry an element you
 * know is on @p head. @p list should be an empty list or a list you do not
 * care about losing its data.
 *
 * @param list a new list to add all removed entries
 * @param head a list with entries
 * @param entry an entry within head, could be the head itself and if so we
 *won't cut the list
 */
static inline void list_cut_position(struct list_head *list,
                                     struct list_head *head,
                                     struct list_head *entry) {
  if (list_empty(head))
    return;
  if (list_is_singular(head) && (head->next != entry && head != entry))
    return;
  if (entry == head)
    INIT_LIST_HEAD(list);
  else
    __list_cut_position(list, head, entry);
}

/**
 * Join two lists.
 *
 * @param list new list to add
 * @param head place to add it in the first list
 */
static inline void list_splice(struct list_head *list, struct list_head *head) {
  if (!list_empty(list))
    __list_splice(list, head, head->next);
}

/**
 * Join two lists, each list being a queue.
 *
 * @param list new list to add
 * @param head place to add it in the first list
 */
static inline void list_splice_tail(struct list_head *list,
                                    struct list_head *head) {
  if (!list_empty(list))
    __list_splice(list, head->prev, head);
}

/**
 * Join two lists and reinitialise the emptied list.
 *
 * @param list new list to add and to be reinitialised
 * @param head place to add it in the first list
 */
static inline void list_splice_init(struct list_head *list,
                                    struct list_head *head) {
  if (!list_empty(list)) {
    __list_splice(list, head, head->next);
    INIT_LIST_HEAD(list);
  }
}

/**
 * Join two lists, each list being a queue, and reinitialise the emptied list.
 *
 * @param list new list to add
 * @param head place to add it in the first list
 */
static inline void list_splice_tail_init(struct list_head *list,
                                         struct list_head *head) {
  if (!list_empty(list)) {
    __list_splice(list, head->prev, head);
    INIT_LIST_HEAD(list);
  }
}

/**
 * Get the struct for this entry.
 *
 * @param ptr struct list head pointer
 * @param type type of the struct this is embedded in
 * @param member name of the list struct within the struct
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

/**
 * Get the first element from a list.
 *
 * @param ptr list head to take the element from
 * @param type type of the struct this is embedded in
 * @param member name of the list struct within the struct
 */
#define list_first_entry(ptr, type, member)                                    \
  list_entry((ptr)->next, type, member)

/**
 * Get the next element from a list.
 *
 * @param ptr list head to take the element from
 * @param type type of the struct this is embedded in
 * @param member name of the list struct within the struct
 */
#define list_next_entry(ptr, type, member)                                     \
  list_entry((ptr)->member.next, type, member)

/**
 * Iterate over a list.
 *
 * @param pos struct list head to use as a loop cursor
 * @param head head for your list
 */
#define list_for_each(pos, head)                                               \
  for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * Iterate over a list backwards.
 *
 * @param pos struct list head to use as a loop cursor
 * @param head head for your list
 */
#define list_for_each_prev(pos, head)                                          \
  for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * Iterate over a list safe against removal of list entry.
 *
 * @param pos struct list head to use as a loop cursor
 * @param n another struct list head to use as temporary storage
 * @param head head for your list
 */
#define list_for_each_safe(pos, n, head)                                       \
  for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

/**
 * Iterate over a list backwards safe against removal of list entry.
 *
 * @param pos struct list head to use as a loop cursor
 * @param n another struct list head to use as temporary storage
 * @param head head for your list
 */
#define list_for_each_prev_safe(pos, n, head)                                  \
  for (pos = (head)->prev, n = pos->prev; pos != (head); pos = n, n = pos->prev)

/**
 * Iterate over list of given type.
 *
 * @param pos type pointer to use as a loop cursor
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry(pos, head, member)                                 \
  for (pos = list_entry((head)->next, typeof(*pos), member);                   \
       &pos->member != (head);                                                 \
       pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * Iterate backwards over list of given type.
 *
 * @param pos type pointer to use as a loop cursor
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_reverse(pos, head, member)                         \
  for (pos = list_entry((head)->prev, typeof(*pos), member);                   \
       &pos->member != (head);                                                 \
       pos = list_entry(pos->member.prev, typeof(*pos), member))

/**
 * Prepare an entry for use in continue.
 *
 * @param pos type pointer to use as a start point
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_prepare_entry(pos, head, member)                                  \
  ((pos) ?: list_entry(head, typeof(*pos), member))

/**
 * Continue iteration over list of given type.
 *
 * @param pos type pointer to use as a loop cursor
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_continue(pos, head, member)                        \
  for (pos = list_entry(pos->member.next, typeof(*pos), member);               \
       &pos->member != (head);                                                 \
       pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * Continue iteration backwards from the given point.
 *
 * @param pos type pointer to use as a loop cursor
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_continue_reverse(pos, head, member)                \
  for (pos = list_entry(pos->member.prev, typeof(*pos), member);               \
       &pos->member != (head);                                                 \
       pos = list_entry(pos->member.prev, typeof(*pos), member))

/**
 * Iterate over list of given type from the current point.
 *
 * @param pos type pointer to use as a loop cursor
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_from(pos, head, member)                            \
  for (; &pos->member != (head);                                               \
       pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * Iterate over list of given type safe against removal of list entry.
 *
 * @param pos type pointer to use as a loop counter
 * @param n another type pointer to use as temporary storage
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_safe(pos, n, head, member)                         \
  for (pos = list_entry((head)->next, typeof(*pos), member),                   \
      n = list_entry(pos->member.next, typeof(*pos), member);                  \
       &pos->member != (head);                                                 \
       pos = n, n = list_entry(n->member.next, typeof(*n), member))

/**
 * Continue list iteration safe against removal
 *
 * @param pos type pointer to use as a loop counter
 * @param n another type pointer to use as temporary storage
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_safe_continue(pos, n, head, member)                \
  for (pos = list_entry(pos->member.next, typeof(*pos), member),               \
      n = list_entry(pos->member.next, typeof(*pos), member);                  \
       &pos->member != (head);                                                 \
       pos = n, n = list_entry(n->member.next, typeof(*n), member))

/**
 * Iterate over list from current point safe agains removal
 *
 * @param pos type pointer to use as a loop counter
 * @param n another type pointer to use as temporary storage
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_safe_from(pos, n, head, member)                    \
  for (n = list_entry(pos->member.next, typeof(*pos), member);                 \
       &pos->member != (head);                                                 \
       pos = n, n = list_entry(n->member.next, typeof(*n), member))

/**
 * Iterate backwards over list safe against removal
 *
 * @param pos type pointer to use as a loop counter
 * @param n another type pointer to use as temporary storage
 * @param head head for your list
 * @param member name of the list structure within the struct
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)                 \
  for (pos = list_entry((head)->prev, typeof(*pos), member),                   \
      n = list_entry(pos->member.prev, typeof(*pos), member);                  \
       &pos->member != (head);                                                 \
       pos = n, n = list_entry(n->member.prev, typeof(*n), member))

/**
 * Reset a stale safe against removal of list entry loop
 *
 * @param pos the loop cursor used in the loop
 * @param n temporary storage used in the loop
 * @param member name of the list structure within the struct
 */
#define list_safe_reset_next(pos, n, member)                                   \
  n = list_entry(pos->member.next, typeof(*pos), member)

#endif /* LIST_H_ */
