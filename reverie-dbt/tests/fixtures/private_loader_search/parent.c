#ifndef PARENT_VALUE
#define PARENT_VALUE 100
#endif
extern int leaf_value(void);
int parent_value(void) {
  return PARENT_VALUE + leaf_value();
}
