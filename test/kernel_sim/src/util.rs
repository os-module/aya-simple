#[inline]
/// Round up `x` to the nearest multiple of `align`.
pub fn round_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_up() {
        assert_eq!(round_up(0, 4), 0);
        assert_eq!(round_up(1, 4), 4);
        assert_eq!(round_up(2, 4), 4);
        assert_eq!(round_up(3, 4), 4);
        assert_eq!(round_up(4, 4), 4);
        assert_eq!(round_up(5, 4), 8);
        assert_eq!(round_up(6, 4), 8);
        assert_eq!(round_up(7, 4), 8);
        assert_eq!(round_up(8, 4), 8);
    }
}

/// See https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
pub const BPF_FUNC_MAPPER: &[&str] = &[
    "unspec",
    "map_lookup_elem",
    "map_update_elem",
    "map_delete_elem",
    "probe_read",
    "ktime_get_ns",
    "trace_printk",
    "get_prandom_u32",
    "get_smp_processor_id",
    "skb_store_bytes",
    "l3_csum_replace",
    "l4_csum_replace",
    "tail_call",
    "clone_redirect",
    "get_current_pid_tgid",
    "get_current_uid_gid",
    "get_current_comm",
    "get_cgroup_classid",
    "skb_vlan_push",
    "skb_vlan_pop",
    "skb_get_tunnel_key",
    "skb_set_tunnel_key",
    "perf_event_read",
    "redirect",
    "get_route_realm",
    "perf_event_output",
    "skb_load_bytes",
    "get_stackid",
    "csum_diff",
    "skb_get_tunnel_opt",
    "skb_set_tunnel_opt",
    "skb_change_proto",
    "skb_change_type",
    "skb_under_cgroup",
    "get_hash_recalc",
    "get_current_task",
    "probe_write_user",
    "current_task_under_cgroup",
    "skb_change_tail",
    "skb_pull_data",
    "csum_update",
    "set_hash_invalid",
    "get_numa_node_id",
    "skb_change_head",
    "xdp_adjust_head",
    "probe_read_str",
    "get_socket_cookie",
    "get_socket_uid",
    "set_hash",
    "setsockopt",
    "skb_adjust_room",
    "redirect_map",
    "sk_redirect_map",
    "sock_map_update",
    "xdp_adjust_meta",
    "perf_event_read_value",
    "perf_prog_read_value",
    "getsockopt",
    "override_return",
    "sock_ops_cb_flags_set",
    "msg_redirect_map",
    "msg_apply_bytes",
    "msg_cork_bytes",
    "msg_pull_data",
    "bind",
    "xdp_adjust_tail",
    "skb_get_xfrm_state",
    "get_stack",
    "skb_load_bytes_relative",
    "fib_lookup",
    "sock_hash_update",
    "msg_redirect_hash",
    "sk_redirect_hash",
    "lwt_push_encap",
    "lwt_seg6_store_bytes",
    "lwt_seg6_adjust_srh",
    "lwt_seg6_action",
    "rc_repeat",
    "rc_keydown",
    "skb_cgroup_id",
    "get_current_cgroup_id",
    "get_local_storage",
    "sk_select_reuseport",
    "skb_ancestor_cgroup_id",
    "sk_lookup_tcp",
    "sk_lookup_udp",
    "sk_release",
    "map_push_elem",
    "map_pop_elem",
    "map_peek_elem",
    "msg_push_data",
    "msg_pop_data",
    "rc_pointer_rel",
    "spin_lock",
    "spin_unlock",
    "sk_fullsock",
    "tcp_sock",
    "skb_ecn_set_ce",
    "get_listener_sock",
    "skc_lookup_tcp",
    "tcp_check_syncookie",
    "sysctl_get_name",
    "sysctl_get_current_value",
    "sysctl_get_new_value",
    "sysctl_set_new_value",
    "strtol",
    "strtoul",
    "sk_storage_get",
    "sk_storage_delete",
    "send_signal",
    "tcp_gen_syncookie",
    "skb_output",
    "probe_read_user",
    "probe_read_kernel",
    "probe_read_user_str",
    "probe_read_kernel_str",
    "tcp_send_ack",
    "send_signal_thread",
    "jiffies64",
    "read_branch_records",
    "get_ns_current_pid_tgid",
    "xdp_output",
    "get_netns_cookie",
    "get_current_ancestor_cgroup_id",
    "sk_assign",
    "ktime_get_boot_ns",
    "seq_printf",
    "seq_write",
    "sk_cgroup_id",
    "sk_ancestor_cgroup_id",
    "ringbuf_output",
    "ringbuf_reserve",
    "ringbuf_submit",
    "ringbuf_discard",
    "ringbuf_query",
    "csum_level",
    "skc_to_tcp6_sock",
    "skc_to_tcp_sock",
    "skc_to_tcp_timewait_sock",
    "skc_to_tcp_request_sock",
    "skc_to_udp6_sock",
    "get_task_stack",
    "load_hdr_opt",
    "store_hdr_opt",
    "reserve_hdr_opt",
    "inode_storage_get",
    "inode_storage_delete",
    "d_path",
    "copy_from_user",
    "snprintf_btf",
    "seq_printf_btf",
    "skb_cgroup_classid",
    "redirect_neigh",
    "per_cpu_ptr",
    "this_cpu_ptr",
    "redirect_peer",
    "task_storage_get",
    "task_storage_delete",
    "get_current_task_btf",
    "bprm_opts_set",
    "ktime_get_coarse_ns",
    "ima_inode_hash",
    "sock_from_file",
    "check_mtu",
    "for_each_map_elem",
    "snprintf",
    "sys_bpf",
    "btf_find_by_name_kind",
    "sys_close",
    "timer_init",
    "timer_set_callback",
    "timer_start",
    "timer_cancel",
    "get_func_ip",
    "get_attach_cookie",
    "task_pt_regs",
    "get_branch_snapshot",
    "trace_vprintk",
    "skc_to_unix_sock",
    "kallsyms_lookup_name",
    "find_vma",
    "loop",
    "strncmp",
    "get_func_arg",
    "get_func_ret",
    "get_func_arg_cnt",
    "get_retval",
    "set_retval",
    "xdp_get_buff_len",
    "xdp_load_bytes",
    "xdp_store_bytes",
    "copy_from_user_task",
    "skb_set_tstamp",
    "ima_file_hash",
    "kptr_xchg",
    "map_lookup_percpu_elem",
    "skc_to_mptcp_sock",
    "dynptr_from_mem",
    "ringbuf_reserve_dynptr",
    "ringbuf_submit_dynptr",
    "ringbuf_discard_dynptr",
    "dynptr_read",
    "dynptr_write",
    "dynptr_data",
    "tcp_raw_gen_syncookie_ipv4",
    "tcp_raw_gen_syncookie_ipv6",
    "tcp_raw_check_syncookie_ipv4",
    "tcp_raw_check_syncookie_ipv6",
    "ktime_get_tai_ns",
    "user_ringbuf_drain",
    "cgrp_storage_get",
    "cgrp_storage_delete",
];

// #define ___BPF_FUNC_MAPPER(FN, ctx...)			\
// FN(unspec, 0, ##ctx)				\
// FN(map_lookup_elem, 1, ##ctx)			\
// FN(map_update_elem, 2, ##ctx)			\
// FN(map_delete_elem, 3, ##ctx)			\
// FN(probe_read, 4, ##ctx)			\
// FN(ktime_get_ns, 5, ##ctx)			\
// FN(trace_printk, 6, ##ctx)			\
// FN(get_prandom_u32, 7, ##ctx)			\
// FN(get_smp_processor_id, 8, ##ctx)		\
// FN(skb_store_bytes, 9, ##ctx)			\
// FN(l3_csum_replace, 10, ##ctx)			\
// FN(l4_csum_replace, 11, ##ctx)			\
// FN(tail_call, 12, ##ctx)			\
// FN(clone_redirect, 13, ##ctx)			\
// FN(get_current_pid_tgid, 14, ##ctx)		\
// FN(get_current_uid_gid, 15, ##ctx)		\
// FN(get_current_comm, 16, ##ctx)			\
// FN(get_cgroup_classid, 17, ##ctx)		\
// FN(skb_vlan_push, 18, ##ctx)			\
// FN(skb_vlan_pop, 19, ##ctx)			\
// FN(skb_get_tunnel_key, 20, ##ctx)		\
// FN(skb_set_tunnel_key, 21, ##ctx)		\
// FN(perf_event_read, 22, ##ctx)			\
// FN(redirect, 23, ##ctx)				\
// FN(get_route_realm, 24, ##ctx)			\
// FN(perf_event_output, 25, ##ctx)		\
// FN(skb_load_bytes, 26, ##ctx)			\
// FN(get_stackid, 27, ##ctx)			\
// FN(csum_diff, 28, ##ctx)			\
// FN(skb_get_tunnel_opt, 29, ##ctx)		\
// FN(skb_set_tunnel_opt, 30, ##ctx)		\
// FN(skb_change_proto, 31, ##ctx)			\
// FN(skb_change_type, 32, ##ctx)			\
// FN(skb_under_cgroup, 33, ##ctx)			\
// FN(get_hash_recalc, 34, ##ctx)			\
// FN(get_current_task, 35, ##ctx)			\
// FN(probe_write_user, 36, ##ctx)			\
// FN(current_task_under_cgroup, 37, ##ctx)	\
// FN(skb_change_tail, 38, ##ctx)			\
// FN(skb_pull_data, 39, ##ctx)			\
// FN(csum_update, 40, ##ctx)			\
// FN(set_hash_invalid, 41, ##ctx)			\
// FN(get_numa_node_id, 42, ##ctx)			\
// FN(skb_change_head, 43, ##ctx)			\
// FN(xdp_adjust_head, 44, ##ctx)			\
// FN(probe_read_str, 45, ##ctx)			\
// FN(get_socket_cookie, 46, ##ctx)		\
// FN(get_socket_uid, 47, ##ctx)			\
// FN(set_hash, 48, ##ctx)				\
// FN(setsockopt, 49, ##ctx)			\
// FN(skb_adjust_room, 50, ##ctx)			\
// FN(redirect_map, 51, ##ctx)			\
// FN(sk_redirect_map, 52, ##ctx)			\
// FN(sock_map_update, 53, ##ctx)			\
// FN(xdp_adjust_meta, 54, ##ctx)			\
// FN(perf_event_read_value, 55, ##ctx)		\
// FN(perf_prog_read_value, 56, ##ctx)		\
// FN(getsockopt, 57, ##ctx)			\
// FN(override_return, 58, ##ctx)			\
// FN(sock_ops_cb_flags_set, 59, ##ctx)		\
// FN(msg_redirect_map, 60, ##ctx)			\
// FN(msg_apply_bytes, 61, ##ctx)			\
// FN(msg_cork_bytes, 62, ##ctx)			\
// FN(msg_pull_data, 63, ##ctx)			\
// FN(bind, 64, ##ctx)				\
// FN(xdp_adjust_tail, 65, ##ctx)			\
// FN(skb_get_xfrm_state, 66, ##ctx)		\
// FN(get_stack, 67, ##ctx)			\
// FN(skb_load_bytes_relative, 68, ##ctx)		\
// FN(fib_lookup, 69, ##ctx)			\
// FN(sock_hash_update, 70, ##ctx)			\
// FN(msg_redirect_hash, 71, ##ctx)		\
// FN(sk_redirect_hash, 72, ##ctx)			\
// FN(lwt_push_encap, 73, ##ctx)			\
// FN(lwt_seg6_store_bytes, 74, ##ctx)		\
// FN(lwt_seg6_adjust_srh, 75, ##ctx)		\
// FN(lwt_seg6_action, 76, ##ctx)			\
// FN(rc_repeat, 77, ##ctx)			\
// FN(rc_keydown, 78, ##ctx)			\
// FN(skb_cgroup_id, 79, ##ctx)			\
// FN(get_current_cgroup_id, 80, ##ctx)		\
// FN(get_local_storage, 81, ##ctx)		\
// FN(sk_select_reuseport, 82, ##ctx)		\
// FN(skb_ancestor_cgroup_id, 83, ##ctx)		\
// FN(sk_lookup_tcp, 84, ##ctx)			\
// FN(sk_lookup_udp, 85, ##ctx)			\
// FN(sk_release, 86, ##ctx)			\
// FN(map_push_elem, 87, ##ctx)			\
// FN(map_pop_elem, 88, ##ctx)			\
// FN(map_peek_elem, 89, ##ctx)			\
// FN(msg_push_data, 90, ##ctx)			\
// FN(msg_pop_data, 91, ##ctx)			\
// FN(rc_pointer_rel, 92, ##ctx)			\
// FN(spin_lock, 93, ##ctx)			\
// FN(spin_unlock, 94, ##ctx)			\
// FN(sk_fullsock, 95, ##ctx)			\
// FN(tcp_sock, 96, ##ctx)				\
// FN(skb_ecn_set_ce, 97, ##ctx)			\
// FN(get_listener_sock, 98, ##ctx)		\
// FN(skc_lookup_tcp, 99, ##ctx)			\
// FN(tcp_check_syncookie, 100, ##ctx)		\
// FN(sysctl_get_name, 101, ##ctx)			\
// FN(sysctl_get_current_value, 102, ##ctx)	\
// FN(sysctl_get_new_value, 103, ##ctx)		\
// FN(sysctl_set_new_value, 104, ##ctx)		\
// FN(strtol, 105, ##ctx)				\
// FN(strtoul, 106, ##ctx)				\
// FN(sk_storage_get, 107, ##ctx)			\
// FN(sk_storage_delete, 108, ##ctx)		\
// FN(send_signal, 109, ##ctx)			\
// FN(tcp_gen_syncookie, 110, ##ctx)		\
// FN(skb_output, 111, ##ctx)			\
// FN(probe_read_user, 112, ##ctx)			\
// FN(probe_read_kernel, 113, ##ctx)		\
// FN(probe_read_user_str, 114, ##ctx)		\
// FN(probe_read_kernel_str, 115, ##ctx)		\
// FN(tcp_send_ack, 116, ##ctx)			\
// FN(send_signal_thread, 117, ##ctx)		\
// FN(jiffies64, 118, ##ctx)			\
// FN(read_branch_records, 119, ##ctx)		\
// FN(get_ns_current_pid_tgid, 120, ##ctx)		\
// FN(xdp_output, 121, ##ctx)			\
// FN(get_netns_cookie, 122, ##ctx)		\
// FN(get_current_ancestor_cgroup_id, 123, ##ctx)	\
// FN(sk_assign, 124, ##ctx)			\
// FN(ktime_get_boot_ns, 125, ##ctx)		\
// FN(seq_printf, 126, ##ctx)			\
// FN(seq_write, 127, ##ctx)			\
// FN(sk_cgroup_id, 128, ##ctx)			\
// FN(sk_ancestor_cgroup_id, 129, ##ctx)		\
// FN(ringbuf_output, 130, ##ctx)			\
// FN(ringbuf_reserve, 131, ##ctx)			\
// FN(ringbuf_submit, 132, ##ctx)			\
// FN(ringbuf_discard, 133, ##ctx)			\
// FN(ringbuf_query, 134, ##ctx)			\
// FN(csum_level, 135, ##ctx)			\
// FN(skc_to_tcp6_sock, 136, ##ctx)		\
// FN(skc_to_tcp_sock, 137, ##ctx)			\
// FN(skc_to_tcp_timewait_sock, 138, ##ctx)	\
// FN(skc_to_tcp_request_sock, 139, ##ctx)		\
// FN(skc_to_udp6_sock, 140, ##ctx)		\
// FN(get_task_stack, 141, ##ctx)			\
// FN(load_hdr_opt, 142, ##ctx)			\
// FN(store_hdr_opt, 143, ##ctx)			\
// FN(reserve_hdr_opt, 144, ##ctx)			\
// FN(inode_storage_get, 145, ##ctx)		\
// FN(inode_storage_delete, 146, ##ctx)		\
// FN(d_path, 147, ##ctx)				\
// FN(copy_from_user, 148, ##ctx)			\
// FN(snprintf_btf, 149, ##ctx)			\
// FN(seq_printf_btf, 150, ##ctx)			\
// FN(skb_cgroup_classid, 151, ##ctx)		\
// FN(redirect_neigh, 152, ##ctx)			\
// FN(per_cpu_ptr, 153, ##ctx)			\
// FN(this_cpu_ptr, 154, ##ctx)			\
// FN(redirect_peer, 155, ##ctx)			\
// FN(task_storage_get, 156, ##ctx)		\
// FN(task_storage_delete, 157, ##ctx)		\
// FN(get_current_task_btf, 158, ##ctx)		\
// FN(bprm_opts_set, 159, ##ctx)			\
// FN(ktime_get_coarse_ns, 160, ##ctx)		\
// FN(ima_inode_hash, 161, ##ctx)			\
// FN(sock_from_file, 162, ##ctx)			\
// FN(check_mtu, 163, ##ctx)			\
// FN(for_each_map_elem, 164, ##ctx)		\
// FN(snprintf, 165, ##ctx)			\
// FN(sys_bpf, 166, ##ctx)				\
// FN(btf_find_by_name_kind, 167, ##ctx)		\
// FN(sys_close, 168, ##ctx)			\
// FN(timer_init, 169, ##ctx)			\
// FN(timer_set_callback, 170, ##ctx)		\
// FN(timer_start, 171, ##ctx)			\
// FN(timer_cancel, 172, ##ctx)			\
// FN(get_func_ip, 173, ##ctx)			\
// FN(get_attach_cookie, 174, ##ctx)		\
// FN(task_pt_regs, 175, ##ctx)			\
// FN(get_branch_snapshot, 176, ##ctx)		\
// FN(trace_vprintk, 177, ##ctx)			\
// FN(skc_to_unix_sock, 178, ##ctx)		\
// FN(kallsyms_lookup_name, 179, ##ctx)		\
// FN(find_vma, 180, ##ctx)			\
// FN(loop, 181, ##ctx)				\
// FN(strncmp, 182, ##ctx)				\
// FN(get_func_arg, 183, ##ctx)			\
// FN(get_func_ret, 184, ##ctx)			\
// FN(get_func_arg_cnt, 185, ##ctx)		\
// FN(get_retval, 186, ##ctx)			\
// FN(set_retval, 187, ##ctx)			\
// FN(xdp_get_buff_len, 188, ##ctx)		\
// FN(xdp_load_bytes, 189, ##ctx)			\
// FN(xdp_store_bytes, 190, ##ctx)			\
// FN(copy_from_user_task, 191, ##ctx)		\
// FN(skb_set_tstamp, 192, ##ctx)			\
// FN(ima_file_hash, 193, ##ctx)			\
// FN(kptr_xchg, 194, ##ctx)			\
// FN(map_lookup_percpu_elem, 195, ##ctx)		\
// FN(skc_to_mptcp_sock, 196, ##ctx)		\
// FN(dynptr_from_mem, 197, ##ctx)			\
// FN(ringbuf_reserve_dynptr, 198, ##ctx)		\
// FN(ringbuf_submit_dynptr, 199, ##ctx)		\
// FN(ringbuf_discard_dynptr, 200, ##ctx)		\
// FN(dynptr_read, 201, ##ctx)			\
// FN(dynptr_write, 202, ##ctx)			\
// FN(dynptr_data, 203, ##ctx)			\
// FN(tcp_raw_gen_syncookie_ipv4, 204, ##ctx)	\
// FN(tcp_raw_gen_syncookie_ipv6, 205, ##ctx)	\
// FN(tcp_raw_check_syncookie_ipv4, 206, ##ctx)	\
// FN(tcp_raw_check_syncookie_ipv6, 207, ##ctx)	\
// FN(ktime_get_tai_ns, 208, ##ctx)		\
// FN(user_ringbuf_drain, 209, ##ctx)		\
// FN(cgrp_storage_get, 210, ##ctx)		\
// FN(cgrp_storage_delete, 211, ##ctx)		\
