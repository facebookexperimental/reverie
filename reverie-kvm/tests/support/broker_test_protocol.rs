// Source-only launcher protocol shared by the two compiled artifacts.
// These strings locate a capability; they are never admission authority.
pub const CHANNEL_ENV: &str = "REVERIE_KVM_TEST_BROKER_CHANNEL";
pub const NONCE_ENV: &str = "REVERIE_KVM_TEST_BROKER_NONCE";
pub const CHILD_ENV: &str = "REVERIE_LEADER_EXEC_CHILD";

pub fn selected(test: &str) -> bool {
    matches!(
        test,
        "pdeathsig::unchanged_six_check_state_matches_native_controlled"
            | "pdeathsig::direct_host_and_unopted_control_preserve_nonzero_refusal"
            | "pdeathsig::creator_thread_death_and_clear_match_native_shared_pending"
            | "pdeathsig::ignored_parent_death_retains_blocked_and_does_not_resurrect_unblocked"
            | "pdeathsig::enrolled_retained_image_exec_preserves_setting_and_actual_creator_delivery"
            | "pdeathsig::actual_creator_death_wakes_controlled_pause_and_nanosleep"
            | "pdeathsig::linger_process::creator_process_queued_tcp_exit_publishes_before_peer_drain"
            | "executor::tests::terminal_cleanup_preserves_live_shared_table_and_does_not_wait_for_its_lock"
            | "executor::tests::terminal_cleanup_retires_socket_despite_fdinfo_observer_table_pin"
            | "terminal_cleanup::tests::dropped_waiter_keeps_native_wait_and_owned_service_alive"
            | "executor::tests::pdeath_abi_adoption_full_width_and_scalar_copyout_are_exact"
            | "executor::tests::pdeath_close_replacement_and_exec_cloexec_require_owned_completion_authority"
            | "executor::tests::pdeath_creator_thread_exit_publishes_process_si_user_once"
            | "executor::tests::pdeath_enrolled_raw_waits_refuse_before_effect_and_capture_remains_supported"
            | "executor::tests::pdeath_exec_uses_image_boundary_and_cleanup_never_impersonates_it"
            | "executor::tests::pdeath_finite_domain_rejects_unmodeled_io_and_shared_task_creation_before_effects"
            | "executor::tests::pdeath_ignored_generation_obeys_mask_observer_and_real_disposition_transitions"
            | "executor::tests::pdeath_late_clear_preserves_frozen_event_and_disposition_generation_discards_it"
            | "executor::tests::pdeath_mutable_timeout_readiness_refuses_before_original_or_injected_effects"
            | "executor::tests::pdeath_original_preflight_is_exact_uncached_and_preserves_zero_readiness"
            | "executor::tests::pdeath_pipe_chld_ignore_and_standard_coalescing_preserve_first_siginfo"
            | "executor::tests::pdeath_publication_failure_retains_exact_prefix_and_survives_sender_cleanup"
            | "executor::tests::pdeath_real_ignore_transition_invalidates_only_the_frozen_generation"
            | "executor::tests::pdeath_registration_reset_sticky_domain_and_exec_capability_gain"
            | "executor::tests::pdeath_reparented_sibling_death_repeats_but_reused_creator_tid_does_not"
            | "executor::tests::pdeath_retained_exec_preserves_permission_and_copyin_errors_after_admission"
            | "executor::tests::pdeath_retained_exec_rejects_missing_or_dynamic_authority_and_stale_callback_identity"
            | "executor::tests::pdeath_retained_exec_snapshot_survives_path_mutation_and_consumes_exact_conversion_once"
            | "executor::tests::pdeath_sendfile_checks_both_owned_endpoints_before_offset_or_output_changes"
            | "executor::tests::pdeath_signal_zero_covers_group_exec_empty_and_ignored_batches"
            | "executor::tests::pdeath_signal_zero_waits_for_publication_without_reviving_delivery"
            | "executor::tests::pdeath_stale_registration_get_and_frozen_receiver_do_not_target_reused_pid"
            | "executor::tests::pdeath_unenrolled_pointer_readiness_and_enrolled_scalar_zero_remain_supported"
            | "runtime::parent_death_tests::initial_exec_preflight_requires_original_context_and_keeps_enrollment_after_replacement"
            | "runtime::parent_death_tests::original_exec_callback_drop_revokes_staged_image_without_injection"
    )
}
