/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

const VALIDATE_SCRIPT: &str = include_str!("../../validate.sh");

#[test]
fn validation_ledger_writer_follows_the_discovered_parent() {
    const LEDGER_SELECTION: &str = r#"if [[ -n $DEV_HERMIT_PARENT ]]; then
    VALIDATION_LEDGER_TOOL="$DEV_HERMIT_PARENT/ci-hub/ledger/validate_rows.py"
else
    VALIDATION_LEDGER_TOOL="${HOME:?HOME is required}/work/dev-hermit/ci-hub/ledger/validate_rows.py"
fi"#;

    assert!(
        VALIDATE_SCRIPT.contains(LEDGER_SELECTION),
        "a nested validation must publish through its discovered parent; the home-relative adapter is only the standalone fallback"
    );
}
