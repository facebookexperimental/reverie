/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use super::*;
use crate::Counter2Global;

struct InputUntilBrokenPipe {
    child_ready: PathBuf,
    source_dropped: PathBuf,
    chunks: Arc<AtomicUsize>,
    dropped: mpsc::Sender<io::Result<()>>,
}

impl Read for InputUntilBrokenPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.child_ready.is_file() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child did not close stdin and announce readiness",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Never manufacture source EOF: the real input pump must discover that
        // the child closed its pipe and drop this reader after EPIPE.
        buffer.fill(b'x');
        self.chunks.fetch_add(1, Ordering::SeqCst);
        Ok(buffer.len())
    }
}

impl Drop for InputUntilBrokenPipe {
    fn drop(&mut self) {
        let result = std::fs::write(&self.source_dropped, b"dropped");
        let _ = self.dropped.send(result);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coordinated_reader_releases_parent_readers_before_pumping() {
    let directory = tempfile::tempdir().unwrap();
    let runner = DbtRunner::new(fake_drrun(directory.path()), fake_client()).unwrap();
    let child_ready = directory.path().join("child-ready");
    let source_dropped = directory.path().join("source-dropped");
    let chunks = Arc::new(AtomicUsize::new(0));
    let (dropped, observed_drop) = mpsc::channel();
    let input = InputUntilBrokenPipe {
        child_ready: child_ready.clone(),
        source_dropped: source_dropped.clone(),
        chunks: Arc::clone(&chunks),
        dropped,
    };

    let mut guest = Command::new("/bin/sh");
    guest
        .args([
            "-c",
            r#"
exec 0<&-
: > "$1"
remaining=300
while [ "$remaining" -gt 0 ]; do
    if [ -f "$2" ]; then
        exit 7
    fi
    remaining=$((remaining - 1))
    sleep 0.01
done
exit 8
"#,
            "reader-ownership-test",
        ])
        .arg(&child_ready)
        .arg(&source_dropped);

    // The fake drrun only forwards this real child process. This exercises the
    // actual coordinated Reader producer and input pump, not native DR/RPC.
    // Exit 7 acknowledges source retirement before the child exits; exit 8 is
    // the bounded failure when a parent Command or lease keeps a reader alive.
    // Both are intentionally nonzero so the existing no-RPC success guard does
    // not obscure this ownership test.
    let result = runner
        .output_with_detached_reader_and_global::<Counter2Global, _>(&guest, input, ())
        .await;

    // Collect input-thread cleanup before TempDir drops, including when the
    // child reported the bounded failure. Cleanup cannot turn exit 8 into 7.
    let dropped = observed_drop.recv_timeout(Duration::from_secs(3));
    let (output, global) = result.expect("coordinated launch failed");
    dropped
        .expect("input source was not dropped after the child exited")
        .expect("could not publish source retirement");
    assert!(child_ready.is_file(), "child never announced the closed fd");
    assert!(
        chunks.load(Ordering::SeqCst) > 0,
        "no input write was attempted"
    );
    assert_eq!(
        output.status.code(),
        Some(7),
        "the input source must retire while the child is alive; stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(global.snapshot(), (0, 0, 0));
}
