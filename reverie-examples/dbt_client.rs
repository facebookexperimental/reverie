/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::path::Path;
use std::path::PathBuf;

/// Find the client built by `reverie-dbt/scripts/build-client.sh` beside the
/// launcher, unless `REVERIE_DBT_CLIENT` explicitly selects another path.
/// An override remains authoritative even if the launcher path is unavailable.
pub(crate) fn find(launcher: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("REVERIE_DBT_CLIENT") {
        return Some(PathBuf::from(path));
    }
    let path = launcher?
        .parent()?
        .join("reverie-dbt-native/libreverie_dbt_client.so");
    path.is_file().then_some(path)
}
