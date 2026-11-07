//! Real installed FullTool routes in this binary's existing Legacy image.
//! Fixture queries run only in ordinary Guest setup, never in a Tool callback.
use std::io::Write;

use fixture::MappingFixtureSnapshot;
use reverie::syscalls::SyscallArgs;
use reverie_inguest::guest::tool_region::BASE;
use reverie_inguest::guest::tool_region::END;
use reverie_inguest::guest::tool_region::mapping_fixture as fixture;

use super::*;

const PAGE: u64 = 4096;
const MSEAL: i64 = 462;
static ROUTE: AtomicU64 = AtomicU64::new(0);
static NUMBER: AtomicI64 = AtomicI64::new(0);
static TARGET: AtomicU64 = AtomicU64::new(0);
static OUTSIDE: AtomicU64 = AtomicU64::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static ENTERED: AtomicU64 = AtomicU64::new(0);
static ORIGINAL: AtomicU64 = AtomicU64::new(0);
static FINAL: AtomicU64 = AtomicU64::new(0);
static NESTED_OUTSIDE: AtomicI64 = AtomicI64::new(i64::MIN);
static MSEAL_SUPPORT: AtomicI64 = AtomicI64::new(i64::MIN);

#[derive(Default)]
struct MappingTool;

#[reverie::tool]
impl Tool for MappingTool {
    type GlobalState = LifecycleGlobal;
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions: Subscription =
            [Sysno::getpid, Sysno::exit_group].into_iter().collect();
        if matches!(ROUTE.load(Ordering::Relaxed), 1 | 2 | 4 | 5) {
            subscriptions.syscall(Sysno::mprotect);
            subscriptions.syscall(Sysno::munmap);
        }
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        match syscall.number() {
            Sysno::exit_group => {
                let callbacks = *guest.thread_state_mut();
                guest.send_rpc(RPC_CALLBACK_COUNT | callbacks).await;
                guest.tail_inject(syscall).await
            }
            Sysno::getpid
                if matches!(ROUTE.load(Ordering::Relaxed), 3 | 6)
                    && ARMED.swap(false, Ordering::Relaxed) =>
            {
                // This is a real callback calling the existing marked site.
                // Hook/trap dispatch supplies the real nested forwarding join.
                ENTERED.fetch_add(1, Ordering::Relaxed);
                let target = TARGET.load(Ordering::Relaxed);
                FINAL.store(target, Ordering::Relaxed);
                let result = pkey_probe_call(NUMBER.load(Ordering::Relaxed), arguments(target));
                let outside = pkey_probe_call(
                    NUMBER.load(Ordering::Relaxed),
                    arguments(OUTSIDE.load(Ordering::Relaxed)),
                );
                NESTED_OUTSIDE.store(outside, Ordering::Relaxed);
                Ok(result)
            }
            Sysno::mprotect | Sysno::munmap if ARMED.swap(false, Ordering::Relaxed) => {
                let original = syscall.into_parts().1.arg0 as u64;
                let route = ROUTE.load(Ordering::Relaxed);
                let final_address = match route {
                    4 => TARGET.load(Ordering::Relaxed),
                    5 => OUTSIDE.load(Ordering::Relaxed),
                    _ => original,
                };
                ENTERED.fetch_add(1, Ordering::Relaxed);
                ORIGINAL.store(original, Ordering::Relaxed);
                FINAL.store(final_address, Ordering::Relaxed);
                let final_call = Syscall::from_raw(
                    syscall.number(),
                    SyscallArgs::new(
                        final_address as usize,
                        PAGE as usize,
                        if syscall.number() == Sysno::mprotect {
                            libc::PROT_READ as usize
                        } else {
                            0
                        },
                        0,
                        0,
                        0,
                    ),
                );
                if route == 2 {
                    guest.tail_inject(final_call).await
                } else {
                    Ok(guest.inject(final_call).await?)
                }
            }
            // Preserve every non-probe call's complete original arguments.
            _ => Ok(guest.inject(syscall).await?),
        }
    }
}

fn arguments(address: u64) -> [u64; 4] {
    [
        address,
        PAGE,
        if NUMBER.load(Ordering::Relaxed) == libc::SYS_mprotect {
            libc::PROT_READ as u64
        } else {
            0
        },
        0,
    ]
}

fn raw(number: i64, args: [u64; 6]) -> i64 {
    // Trusted setup/inspection only; measured mutations use the marked site.
    unsafe { reverie_inguest::trap::raw_syscall6(number, args) }
}

fn outside_page() -> u64 {
    let result = raw(
        libc::SYS_mmap,
        [
            0,
            PAGE,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            u64::MAX,
            0,
        ],
    );
    assert!(result > 0, "outside mmap setup: {result}");
    let address = result as u64;
    assert!(
        address + PAGE <= BASE as u64 || address >= END as u64,
        "outside control aliases owner"
    );
    address
}

fn maps() -> String {
    let text = std::fs::read_to_string("/proc/self/maps").expect("complete actual maps");
    assert!(!text.is_empty() && text.ends_with('\n') && text.len() < 65536);
    text
}

fn mapping(line: &str) -> (u64, u64, &str) {
    let mut fields = line.split_whitespace();
    let range = fields.next().expect("maps range");
    let permissions = fields.next().expect("maps permissions");
    let (start, end) = range.split_once('-').expect("maps interval");
    (
        u64::from_str_radix(start, 16).unwrap(),
        u64::from_str_radix(end, 16).unwrap(),
        permissions,
    )
}

fn owner_maps(text: &str) -> String {
    text.lines()
        .filter(|line| {
            let (start, end, _) = mapping(line);
            start < END as u64 && end > BASE as u64
        })
        .map(|line| format!("{line}\n"))
        .collect()
}

fn permissions(text: &str, address: u64) -> Option<&str> {
    text.lines().find_map(|line| {
        let (start, end, permissions) = mapping(line);
        (start <= address && address < end).then_some(permissions)
    })
}

type Action = unsafe fn(fixture::Backing, *mut MappingFixtureSnapshot, usize) -> i32;
fn snapshot(action: Action) -> (i32, MappingFixtureSnapshot) {
    let mut record = MappingFixtureSnapshot::default();
    let status = unsafe {
        action(
            fixture::Backing::Legacy,
            &mut record,
            std::mem::size_of::<MappingFixtureSnapshot>(),
        )
    };
    (status, record)
}

fn same_owner(before: &MappingFixtureSnapshot, after: &MappingFixtureSnapshot) -> bool {
    let mut expected = *before;
    expected.reuse_base = after.reuse_base;
    expected.reuse_count = after.reuse_count;
    // Complete fixed-width record equality, except the two documented counters.
    snapshot_words(&expected) == snapshot_words(after)
}

fn snapshot_words(record: &MappingFixtureSnapshot) -> [u64; 21] {
    // repr(C), twenty-one initialized u64 fields, no padding or pointer fields.
    const {
        assert!(std::mem::size_of::<MappingFixtureSnapshot>() == 21 * 8);
    }
    unsafe { *(record as *const MappingFixtureSnapshot).cast::<[u64; 21]>() }
}

pub(super) fn run(route_name: &str, operation: &str) {
    let route = match route_name {
        "unsubscribed" => 0,
        "inject" => 1,
        "tail" => 2,
        "nested-hook" => 3,
        "rewrite-protected" => 4,
        "rewrite-outside" => 5,
        "nested-trap" => 6,
        _ => panic!("unknown mapping route"),
    };
    let number = match operation {
        "mprotect" => libc::SYS_mprotect,
        "munmap" => libc::SYS_munmap,
        "mseal" => MSEAL,
        _ => panic!("unknown mapping operation"),
    };
    assert!(number != MSEAL || matches!(route, 3 | 6));
    ROUTE.store(route, Ordering::Relaxed);
    NUMBER.store(number, Ordering::Relaxed);
    if number == MSEAL {
        let page = outside_page();
        let support = raw(MSEAL, [page, PAGE, 0, 0, 0, 0]);
        println!("MAPPING_MSEAL_HOST mapped=1 raw={support}");
        assert!(
            support == 0 || support == -i64::from(libc::ENOSYS),
            "mapped outside mseal host-support setup failed: {support}"
        );
        MSEAL_SUPPORT.store(support, Ordering::Relaxed);
        if support == -i64::from(libc::ENOSYS) {
            println!(
                "MAPPING_MSEAL_UNMEASURED host=ENOSYS kernel_mutation=unmeasured guard_route=required"
            );
        }
        // A successfully sealed page cannot be unmapped; process exit owns it.
    }
    let original_outside = outside_page();
    let nested_outside = outside_page();
    let positive = outside_page();
    let coordinator =
        std::env::var_os(reverie_liteinst::COORDINATOR_ENV).expect("actual coordinator");
    unsafe {
        // Ordinary single-thread setup, clear DF, no prior installed filter.
        reverie_liteinst::install_tool_quiescent::<MappingTool>(std::path::PathBuf::from(
            coordinator,
        ))
    }
    .expect("actual FullTool install");
    assert!(pkey_probe_call(libc::SYS_getppid, [0; 4]) > 0);
    let site = core::ptr::addr_of!(reverie_liteinst_pkey_probe_site);
    let warm = site_counts(site);
    if route == 6 {
        assert_eq!(warm, (0, 0));
    } else {
        assert_eq!(warm, (1, 1));
    }
    let (prepared, before) = snapshot(fixture::prepare);
    assert_eq!(prepared, 0, "same-image owner fixture setup");
    assert_eq!(before.version, 1);
    assert!(before.owner != 0 && before.control != 0 && before.state != 0);
    assert_eq!(before.current_pid, raw(libc::SYS_getpid, [0; 6]) as u64);
    assert_eq!(before.current_tid, raw(libc::SYS_gettid, [0; 6]) as u64);
    assert!(before.alt_bottom < before.alt_top);
    assert_eq!(
        (
            before.live_bytes,
            before.free_bytes,
            before.live_owned,
            before.free_unowned
        ),
        (PAGE, PAGE, 1, 1)
    );
    let before_maps = maps();
    assert_eq!(permissions(&before_maps, before.free_base), Some("---p"));
    assert_eq!(
        unsafe { (before.live_base as *const u8).read_volatile() },
        fixture::SENTINEL
    );
    TARGET.store(before.free_base, Ordering::Relaxed);
    OUTSIDE.store(nested_outside, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let original = if route == 4 {
        original_outside
    } else if matches!(route, 3 | 6) {
        0
    } else {
        before.free_base
    };
    let result = if matches!(route, 3 | 6) {
        pkey_probe_call(libc::SYS_getpid, [0; 4])
    } else {
        pkey_probe_call(number, arguments(original))
    };
    let entered = ENTERED.load(Ordering::Relaxed);
    let recorded_original = ORIGINAL.load(Ordering::Relaxed);
    let final_address = FINAL.load(Ordering::Relaxed);
    let nested_result = NESTED_OUTSIDE.load(Ordering::Relaxed);
    let after_maps = maps();
    let (observed, after) = snapshot(fixture::observe);
    let sentinel = unsafe { (before.live_base as *const u8).read_volatile() };
    let maps_equal = owner_maps(&before_maps) == owner_maps(&after_maps);
    let identity = observed == 0
        && same_owner(&before, &after)
        && after.reuse_base == before.reuse_base
        && after.reuse_count == before.reuse_count;
    let original_intact = route != 4 || permissions(&after_maps, original_outside) == Some("rw-p");
    let outside_effect = route != 5
        || if number == libc::SYS_mprotect {
            permissions(&after_maps, nested_outside) == Some("r--p")
        } else {
            permissions(&after_maps, nested_outside).is_none()
        };
    ARMED.store(false, Ordering::Relaxed);
    let outside_result = pkey_probe_call(number, arguments(positive));
    let positive_maps = maps();
    let outside_positive = if number == MSEAL {
        // Preserve the existing unknown-typed FullTool boundary, not admission.
        outside_result == -i64::from(libc::ENOSYS)
    } else {
        outside_result == 0
            && if number == libc::SYS_mprotect {
                permissions(&positive_maps, positive) == Some("r--p")
            } else {
                permissions(&positive_maps, positive).is_none()
            }
    };
    // Always capture real later lease attempts before the literal regression.
    let (reuse, reused) = snapshot(fixture::reuse);
    let (second_reuse, twice_reused) = snapshot(fixture::reuse);
    let lease_same = reuse == 0
        && second_reuse == 0
        && same_owner(&before, &reused)
        && same_owner(&before, &twice_reused)
        && reused.reuse_base == before.free_base
        && twice_reused.reuse_base == before.free_base
        && reused.reuse_count == 1
        && twice_reused.reuse_count == 2;
    let counters = site_counts(site);
    let expected = if route == 5 {
        0
    } else {
        -i64::from(libc::EPERM)
    };
    let route_seen = match route {
        0 => entered == 0 && recorded_original == 0 && final_address == 0,
        3 | 6 => {
            entered == 1
                && recorded_original == 0
                && final_address == before.free_base
                && nested_result
                    == if number == MSEAL {
                        MSEAL_SUPPORT.load(Ordering::Relaxed)
                    } else {
                        0
                    }
        }
        _ => {
            entered == 1
                && recorded_original == original
                && final_address
                    == if route == 5 {
                        nested_outside
                    } else {
                        before.free_base
                    }
        }
    };
    let physical = if route == 6 {
        counters == (0, 0)
    } else {
        counters.0 == warm.0 && counters.1 > warm.1
    };
    println!(
        "MAPPING_OWNER_FACTS version={} owner={:#x} control={:#x} state={:#x} pid={} tid={} alt_bottom={:#x} alt_top={:#x} live={:#x} live_bytes={} live_owned={} free={:#x} free_bytes={} free_unowned={}",
        before.version,
        before.owner,
        before.control,
        before.state,
        before.current_pid,
        before.current_tid,
        before.alt_bottom,
        before.alt_top,
        before.live_base,
        before.live_bytes,
        before.live_owned,
        before.free_base,
        before.free_bytes,
        before.free_unowned
    );
    println!(
        "MAPPING_OWNER before={before:?} after={after:?} reused={reused:?} twice_reused={twice_reused:?}"
    );
    println!("MAPPING_MAPS_BEFORE_BEGIN\n{before_maps}MAPPING_MAPS_BEFORE_END");
    println!("MAPPING_MAPS_AFTER_BEGIN\n{after_maps}MAPPING_MAPS_AFTER_END");
    println!(
        "MAPPING_ROUTE_LITERAL route={route_name} op={operation} raw={result} expected={expected} entered={entered} original={original:#x} recorded_original={recorded_original:#x} final={final_address:#x} target={:#x} outside_address={nested_outside:#x} maps_equal={} identity={} sentinel={} reuse={reuse} second_reuse={second_reuse} lease_same={} outside={outside_result} outside_positive={} nested_outside={nested_result} original_intact={} outside_effect={} route_seen={} physical={} traps={} hooks={}",
        before.free_base,
        u8::from(maps_equal),
        u8::from(identity),
        sentinel,
        u8::from(lease_same),
        u8::from(outside_positive),
        u8::from(original_intact),
        u8::from(outside_effect),
        u8::from(route_seen),
        u8::from(physical),
        counters.0,
        counters.1
    );
    let finished = unsafe { fixture::finish(fixture::Backing::Legacy) };
    println!("MAPPING_FINISH raw={finished}");
    for page in [original_outside, positive] {
        let _ = raw(libc::SYS_munmap, [page, PAGE, 0, 0, 0, 0]);
    }
    if number != MSEAL {
        let _ = raw(libc::SYS_munmap, [nested_outside, PAGE, 0, 0, 0, 0]);
    }
    std::io::stdout().flush().unwrap();
    let passed = result == expected
        && route_seen
        && maps_equal
        && identity
        && sentinel == fixture::SENTINEL
        && lease_same
        && outside_positive
        && original_intact
        && outside_effect
        && physical
        && finished == 0;
    std::process::exit(if passed { 0 } else { 1 });
}
