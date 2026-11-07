/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Shared launch/RPC types and host observations for the native fixture.
//! The host tests include these types without compiling the native Tool.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use reverie::GlobalTool;
use reverie::Pid;
use serde::Deserialize;
use serde::Serialize;

pub const NONCE: u64 = 73;
pub const EXPECTED_CONTROLLER_PANIC: &str = "LIFECYCLE_EXPECTED_CONTROLLER_RPC_PANIC";

// One host-test observer for this single concrete Global. The standalone Tool
// never reads or constructs it. It is neither a Tool registry nor runtime gate.
static PUBLIC_FAILURE_OBSERVER: Mutex<Option<Arc<PublicFailureObserver>>> = Mutex::new(None);

pub(super) static NO_APPLICATION_RPC_REQUESTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    Invalid,
    SelectedTail,
    OriginalExit,
    SuppressOnce,
    RewriteAway,
    RewriteToTerminal,
    RpcDisconnect,
    NoApplicationRpc,
}

impl Mode {
    pub fn continues(self) -> bool {
        matches!(self, Self::SuppressOnce | Self::RewriteAway)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectPoint {
    #[default]
    None,
    Async,
    Sync,
    ThreadExit,
    ProcessExit,
    AsyncControllerPanic,
    Startup,
}

impl DisconnectPoint {
    pub fn guest_argument(self) -> &'static str {
        match self {
            Self::Async | Self::Sync | Self::AsyncControllerPanic => "6",
            Self::Startup | Self::ThreadExit => "7",
            Self::ProcessExit => "8",
            Self::None => panic!("disconnect case requires an explicit point"),
        }
    }

    fn matches(self, event: &Event) -> bool {
        match event {
            Event::StartHook => self == Self::Startup,
            Event::Disconnect { point } => *point == self,
            Event::ThreadExit { .. } => self == Self::ThreadExit,
            Event::ProcessExit { .. } => self == Self::ProcessExit,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Terminal {
    #[default]
    Exit,
    ExitGroup,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub nonce: u64,
    pub mode: Mode,
    pub disconnect: DisconnectPoint,
    pub terminal: Terminal,
    pub args: [u64; 6],
    pub witness: Option<PathBuf>,
}

impl Config {
    pub fn new(mode: Mode, terminal: Terminal, code: u64) -> Self {
        let config = Self {
            version: 1,
            nonce: NONCE,
            mode,
            disconnect: DisconnectPoint::None,
            terminal,
            args: [code, 17, 34, 51, 68, 85],
            witness: None,
        };
        config.validate();
        config
    }

    pub fn disconnect_at(point: DisconnectPoint) -> Self {
        assert_ne!(point, DisconnectPoint::None);
        let mut config = Self::new(Mode::OriginalExit, Terminal::ExitGroup, 23);
        config.disconnect = point;
        if matches!(
            point,
            DisconnectPoint::Async | DisconnectPoint::Sync | DisconnectPoint::AsyncControllerPanic
        ) {
            config.mode = Mode::RpcDisconnect;
        }
        config.validate();
        config
    }

    pub fn validate(&self) {
        assert_eq!(
            self.version, 1,
            "default configuration is not a fixture launch"
        );
        assert_eq!(self.nonce, NONCE);
        assert_ne!(self.mode, Mode::Invalid);
        assert_eq!(self.mode == Mode::NoApplicationRpc, self.witness.is_some());
        if let Some(path) = &self.witness {
            assert!(path.is_absolute());
            assert_eq!(self.disconnect, DisconnectPoint::None);
            assert_eq!(self.terminal, Terminal::ExitGroup);
            assert_eq!(self.args[0], 23);
        }
        match self.disconnect {
            DisconnectPoint::None => assert_ne!(self.mode, Mode::RpcDisconnect),
            DisconnectPoint::Async
            | DisconnectPoint::Sync
            | DisconnectPoint::AsyncControllerPanic => {
                assert_eq!(self.mode, Mode::RpcDisconnect);
                assert_eq!(self.terminal, Terminal::ExitGroup);
                assert_eq!(self.args[0], 23);
            }
            DisconnectPoint::Startup
            | DisconnectPoint::ThreadExit
            | DisconnectPoint::ProcessExit => {
                assert_eq!(self.mode, Mode::OriginalExit);
                assert_eq!(self.terminal, Terminal::ExitGroup);
                assert_eq!(self.args[0], 23);
            }
        }
        assert!(matches!(self.args[0], 23 | 0x117));
        assert_eq!(self.args[1..], [17, 34, 51, 68, 85]);
        if self.mode.continues() {
            assert_eq!(self.terminal, Terminal::Exit);
            assert_eq!(self.args[0], 23);
        }
        if self.mode == Mode::RewriteToTerminal {
            assert_eq!(self.terminal, Terminal::ExitGroup);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCall {
    pub number: i64,
    pub args: [u64; 6],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    StartHook,
    PostExecHook,
    Disconnect {
        point: DisconnectPoint,
    },
    Attempt {
        observed: RawCall,
        requested_replacement: Option<RawCall>,
    },
    Continued {
        result: i64,
    },
    ThreadExit {
        code: i32,
        attempts: usize,
        drops: usize,
        continued: bool,
    },
    ProcessExit {
        code: i32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub(super) config: Config,
    pub(super) event: Event,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub(super) nonce: u64,
    pub(super) sequence: usize,
}

#[derive(Debug)]
pub struct DisconnectWitness {
    pub sender: i32,
    pub sequence: usize,
    pub event: Event,
}

struct PendingRequest(Arc<AtomicUsize>);

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
pub struct PublicFailureSnapshot {
    pub config: Config,
    pub events: Vec<(i32, Event)>,
    pub globals_created: usize,
    pub globals_dropped: usize,
    pub active_requests: usize,
    pub requests_dropped: usize,
}

pub struct PublicFailureWatch {
    pub request: mpsc::Receiver<DisconnectWitness>,
    pub acknowledge: mpsc::Sender<()>,
    pub global_dropped: mpsc::Receiver<()>,
}

pub struct PublicFailureObserver {
    config: Config,
    events: Mutex<Vec<(i32, Event)>>,
    globals_created: AtomicUsize,
    globals_dropped: AtomicUsize,
    active_requests: AtomicUsize,
    requests_dropped: AtomicUsize,
    request: mpsc::Sender<DisconnectWitness>,
    acknowledgement: Mutex<mpsc::Receiver<()>>,
    global_dropped: mpsc::Sender<()>,
}

impl PublicFailureObserver {
    pub fn snapshot(&self) -> PublicFailureSnapshot {
        PublicFailureSnapshot {
            config: self.config.clone(),
            events: self.events.lock().unwrap().clone(),
            globals_created: self.globals_created.load(Ordering::SeqCst),
            globals_dropped: self.globals_dropped.load(Ordering::SeqCst),
            active_requests: self.active_requests.load(Ordering::SeqCst),
            requests_dropped: self.requests_dropped.load(Ordering::SeqCst),
        }
    }
}

struct PublicPendingRequest(Arc<PublicFailureObserver>);

impl Drop for PublicPendingRequest {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::SeqCst);
        self.0.requests_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct LifecycleGlobal {
    config: Config,
    host_pid: u32,
    events: Mutex<Vec<(i32, Event)>>,
    disconnect_witness: Mutex<Option<mpsc::Sender<DisconnectWitness>>>,
    cancelled_requests: Arc<AtomicUsize>,
    public_observer: Option<Arc<PublicFailureObserver>>,
}

impl Default for LifecycleGlobal {
    fn default() -> Self {
        panic!("LifecycleGlobal requires explicit host initialization");
    }
}

impl LifecycleGlobal {
    /// Arm host-only witnesses before the public runner constructs its Global.
    /// The configuration still travels through the ordinary serialized launch.
    pub fn observe_public_failure(
        config: &Config,
    ) -> (Arc<PublicFailureObserver>, PublicFailureWatch) {
        config.validate();
        assert_eq!(config.disconnect, DisconnectPoint::AsyncControllerPanic);
        let (request, received) = mpsc::channel();
        let (acknowledge, acknowledgement) = mpsc::channel();
        let (global_dropped, dropped) = mpsc::channel();
        let observer = Arc::new(PublicFailureObserver {
            config: config.clone(),
            events: Mutex::new(Vec::new()),
            globals_created: AtomicUsize::new(0),
            globals_dropped: AtomicUsize::new(0),
            active_requests: AtomicUsize::new(0),
            requests_dropped: AtomicUsize::new(0),
            request,
            acknowledgement: Mutex::new(acknowledgement),
            global_dropped,
        });
        assert!(
            PUBLIC_FAILURE_OBSERVER
                .lock()
                .unwrap()
                .replace(Arc::clone(&observer))
                .is_none()
        );
        (
            observer,
            PublicFailureWatch {
                request: received,
                acknowledge,
                global_dropped: dropped,
            },
        )
    }

    /// Host-side observation of the real decoded request. This does not write
    /// a response or any activation/control frame.
    pub fn arm_disconnect(&self) -> mpsc::Receiver<DisconnectWitness> {
        assert_ne!(self.config.disconnect, DisconnectPoint::None);
        let (sender, receiver) = mpsc::channel();
        assert!(
            self.disconnect_witness
                .lock()
                .unwrap()
                .replace(sender)
                .is_none()
        );
        receiver
    }

    pub fn cancelled_requests(&self) -> usize {
        self.cancelled_requests.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> (Config, Vec<(i32, Event)>) {
        (self.config.clone(), self.events.lock().unwrap().clone())
    }
}

#[reverie::global_tool]
impl GlobalTool for LifecycleGlobal {
    type Config = Config;
    type Request = Request;
    type Response = Reply;

    async fn init_global_state(config: &Config) -> Self {
        config.validate();
        let public_observer = if config.disconnect == DisconnectPoint::AsyncControllerPanic {
            let observer = PUBLIC_FAILURE_OBSERVER
                .lock()
                .unwrap()
                .take()
                .expect("public runner observer was not armed on the actual host");
            assert_eq!(observer.config, *config);
            assert_eq!(observer.globals_created.fetch_add(1, Ordering::SeqCst), 0);
            Some(observer)
        } else {
            None
        };
        Self {
            config: config.clone(),
            host_pid: std::process::id(),
            events: Mutex::new(Vec::new()),
            disconnect_witness: Mutex::new(None),
            cancelled_requests: Arc::new(AtomicUsize::new(0)),
            public_observer,
        }
    }

    async fn receive_rpc(&self, from: Pid, request: Request) -> Reply {
        if self.config.mode == Mode::NoApplicationRpc {
            NO_APPLICATION_RPC_REQUESTS.fetch_add(1, Ordering::SeqCst);
            panic!("zero-request Tool sent an application RPC");
        }
        assert_eq!(std::process::id(), self.host_pid);
        assert!(from.as_raw() > 0);
        assert_ne!(from.as_raw() as u32, self.host_pid);
        assert_eq!(request.config, self.config);
        let sequence = {
            let mut events = self.events.lock().unwrap();
            if let Some((owner, _)) = events.first() {
                assert_eq!(from.as_raw(), *owner);
            }
            events.push((from.as_raw(), request.event.clone()));
            events.len()
        };
        if let Some(observer) = &self.public_observer {
            observer
                .events
                .lock()
                .unwrap()
                .push((from.as_raw(), request.event.clone()));
        }
        if self.config.disconnect.matches(&request.event) {
            if let Some(observer) = &self.public_observer {
                assert_eq!(
                    self.config.disconnect,
                    DisconnectPoint::AsyncControllerPanic
                );
                assert_eq!(observer.active_requests.fetch_add(1, Ordering::SeqCst), 0);
                let _pending = PublicPendingRequest(Arc::clone(observer));
                observer
                    .request
                    .send(DisconnectWitness {
                        sender: from.as_raw(),
                        sequence,
                        event: request.event,
                    })
                    .expect("public request witness owner is alive");
                // A separate host observer thread acknowledges receiving the
                // actual request before this deliberate controller-only panic.
                // No event mutex is held while panicking; normal unwinding
                // drops the real connection future and its actual socket.
                observer
                    .acknowledgement
                    .lock()
                    .unwrap()
                    .recv()
                    .expect("public request witness was not acknowledged");
                panic!("{EXPECTED_CONTROLLER_PANIC}");
            }
            let _pending = PendingRequest(Arc::clone(&self.cancelled_requests));
            let sender = self
                .disconnect_witness
                .lock()
                .unwrap()
                .take()
                .expect("host must arm the exact pending request before serving Config");
            sender
                .send(DisconnectWitness {
                    sender: from.as_raw(),
                    sequence,
                    event: request.event,
                })
                .expect("disconnect witness owner is alive");
            // The real server owns and cancels this future. No fabricated
            // response, wire error, native callback or wait status is involved.
            return std::future::pending::<Reply>().await;
        }
        Reply {
            nonce: self.config.nonce,
            sequence,
        }
    }
}

impl Drop for LifecycleGlobal {
    fn drop(&mut self) {
        if let Some(observer) = &self.public_observer {
            observer.globals_dropped.fetch_add(1, Ordering::SeqCst);
            // Do not create a second panic if the enclosing host test already
            // failed. Missing observation remains a failed assertion in it.
            let _ = observer.global_dropped.send(());
        }
    }
}
