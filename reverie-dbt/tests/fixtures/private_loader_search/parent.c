/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef PARENT_VALUE
#define PARENT_VALUE 100
#endif
extern int leaf_value(void);
int parent_value(void) {
  return PARENT_VALUE + leaf_value();
}
