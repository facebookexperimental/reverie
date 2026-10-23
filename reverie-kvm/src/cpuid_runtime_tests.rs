mod cpuid_runtime_controls {
    use reverie::syscalls::SyscallInfo;

    use super::*;

    #[test]
    fn cpuid_boundary_respects_actual_fetch_permissions_and_completed_length() {
        const BOUNDARY: u64 = 0x40_0000;
        for crosses_page in [false, true] {
            let mut backend = KvmBackend::new(16 * 1024 * 1024).expect("actual KVM is mandatory");
            let opcode = if crosses_page {
                &[0x66, 0x0f, 0xa2][..]
            } else {
                &[0x0f, 0xa2][..]
            };
            let mut code = vec![0x90; 0x20_0000 - 2];
            code.extend_from_slice(opcode);
            let mut image = minimal_test_elf(&code);
            image[24..32].copy_from_slice(&(BOUNDARY - 2).to_le_bytes());
            image[104..112].copy_from_slice(&(code.len() as u64).to_le_bytes());
            backend
                .install_static_elf(&image, "/cpuid-fetch-boundary")
                .unwrap();
            backend
                .memory
                .write_raw(
                    0x4000 + 2 * 8,
                    &(BOUNDARY | 0x87 | (1_u64 << 63)).to_le_bytes(),
                )
                .unwrap();
            backend.set_cpuid_interception(true).unwrap();
            assert!(matches!(
                backend
                    .vcpu
                    .run()
                    .unwrap()
                    .expect("test entry admission was unexpectedly closed"),
                VcpuExit::Hlt
            ));
            let fault = backend.static_elf_exception().unwrap().unwrap();
            assert_eq!(fault.instruction_pointer, BOUNDARY - 2);
            assert_eq!(fault.vector, if crosses_page { 14 } else { 13 });
            let selected = backend.cpuid_instruction_exception().unwrap();
            if crosses_page {
                assert!(selected.is_none());
                assert_eq!(backend.vcpu.get_sregs().unwrap().cr2, BOUNDARY);
            } else {
                assert_eq!(
                    selected
                        .expect("complete two-byte CPUID")
                        .instruction
                        .length,
                    2
                );
            }
        }
    }

    #[derive(Default)]
    struct NonElfCpuidTool;

    #[reverie::tool]
    impl reverie::Tool for NonElfCpuidTool {
        type GlobalState = ();
        type ThreadState = ();
        fn subscriptions(_: &()) -> reverie::Subscription {
            let mut subscriptions = reverie::Subscription::none();
            subscriptions.cpuid();
            subscriptions
        }
        async fn handle_thread_start<G: reverie::Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            assert!(
                !guest.has_cpuid_interception(),
                "public non-ELF loop has no CPUID consumer"
            );
            Ok(())
        }
        async fn handle_cpuid_event<G: reverie::Guest<Self>>(
            &self,
            _guest: &mut G,
            _eax: u32,
            _ecx: u32,
        ) -> std::result::Result<reverie::CpuIdResult, reverie::syscalls::Errno> {
            panic!("public non-ELF loop must preserve ordinary CPUID execution");
        }
    }

    fn assert_disarmed(backend: &KvmBackend) {
        assert!(!backend.has_cpuid_interception());
        let mut msrs = kvm_bindings::Msrs::from_entries(&[kvm_bindings::kvm_msr_entry {
            index: 0x140,
            ..Default::default()
        }])
        .unwrap();
        assert_eq!(backend.vcpu.get_msrs(&mut msrs).unwrap(), 1);
        assert_eq!(msrs.as_slice()[0].data & 1, 0);
    }

    #[test]
    fn cpuid_nonconsumer_loops_disarm_actual_prior_owned_msr_state() {
        for previously_armed in [false, true] {
            for use_tool in [false, true] {
                let mut backend =
                    KvmBackend::new(16 * 1024 * 1024).expect("actual KVM is mandatory");
                backend.set_cpuid_interception(previously_armed).unwrap();
                let request = SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]);
                backend.install_syscall(0x1002, 0x2000, request).unwrap();
                backend.memory.write(0x1000, &[0x0f, 0xa2]).unwrap();
                let mut registers = backend.vcpu.get_regs().unwrap();
                registers.rip = 0x1000;
                backend.vcpu.set_regs(&registers).unwrap();
                let mut calls = 0;
                if use_tool {
                    futures::executor::block_on(backend.run_with_tool::<NonElfCpuidTool, _>(
                        (),
                        |actual: &SyscallRequest, _: &GuestMemory| {
                            assert_eq!(*actual, request);
                            calls += 1;
                            41
                        },
                    ))
                    .unwrap();
                } else {
                    backend
                        .run(|call, _| {
                            assert_eq!(call.number(), reverie::syscalls::Sysno::getpid);
                            calls += 1;
                            41
                        })
                        .unwrap();
                }
                assert_eq!(calls, 1);
                assert_disarmed(&backend);
            }
            let mut backend = KvmBackend::new(16 * 1024 * 1024).unwrap();
            backend.set_cpuid_interception(previously_armed).unwrap();
            backend
                .install_static_elf(
                    &minimal_test_elf(&[0x0f, 0xa2, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]),
                    "/direct-cpuid",
                )
                .unwrap();
            let (status, stdout, stderr) = backend.run_static_elf_captured().unwrap();
            assert_eq!(status, 0);
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
            assert_disarmed(&backend);
        }
    }
}
