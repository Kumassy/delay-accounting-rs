#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(extern_types)]
use ::c2rust_out::*;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_GENERIC};
use netlink_packet_core::{NetlinkMessage, NetlinkHeader, NetlinkPayload, constants::{NLM_F_REQUEST}, NetlinkSerializable};
use netlink_packet_generic::{constants::{GENL_HDRLEN, GENL_ID_CTRL}, GenlMessage, ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs}};

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn perror(__s: *const libc::c_char);
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    fn exit(_: libc::c_int) -> !;
    fn __errno_location() -> *mut libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn execvp(
        __file: *const libc::c_char,
        __argv: *const *mut libc::c_char,
    ) -> libc::c_int;
    fn getpid() -> __pid_t;
    fn fork() -> __pid_t;
    static mut optarg: *mut libc::c_char;
    fn getopt(
        ___argc: libc::c_int,
        ___argv: *const *mut libc::c_char,
        __shortopts: *const libc::c_char,
    ) -> libc::c_int;
    static mut optind: libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strncpy(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn socket(
        __domain: libc::c_int,
        __type: libc::c_int,
        __protocol: libc::c_int,
    ) -> libc::c_int;
    fn bind(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t) -> libc::c_int;
    fn recv(
        __fd: libc::c_int,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
    ) -> ssize_t;
    fn sendto(
        __fd: libc::c_int,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
        __addr: *const sockaddr,
        __addr_len: socklen_t,
    ) -> ssize_t;
    fn setsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> libc::c_int;
    fn sigemptyset(__set: *mut sigset_t) -> libc::c_int;
    fn sigaddset(__set: *mut sigset_t, __signo: libc::c_int) -> libc::c_int;
    fn sigprocmask(
        __how: libc::c_int,
        __set: *const sigset_t,
        __oset: *mut sigset_t,
    ) -> libc::c_int;
    fn sigwait(__set: *const sigset_t, __sig: *mut libc::c_int) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type ssize_t = __ssize_t;
pub type pid_t = __pid_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;
pub type socklen_t = __socklen_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type __u8 = libc::c_uchar;
pub type __u16 = libc::c_ushort;
pub type __u32 = libc::c_uint;
pub type __u64 = libc::c_ulonglong;
pub type __kernel_sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_nl {
    pub nl_family: __kernel_sa_family_t,
    pub nl_pad: libc::c_ushort,
    pub nl_pid: __u32,
    pub nl_groups: __u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nlmsghdr {
    pub nlmsg_len: __u32,
    pub nlmsg_type: __u16,
    pub nlmsg_flags: __u16,
    pub nlmsg_seq: __u32,
    pub nlmsg_pid: __u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nlmsgerr {
    pub error: libc::c_int,
    pub msg: nlmsghdr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nlattr {
    pub nla_len: __u16,
    pub nla_type: __u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct genlmsghdr {
    pub cmd: __u8,
    pub version: __u8,
    pub reserved: __u16,
}
pub type C2RustUnnamed = libc::c_uint;
pub const __CTRL_CMD_MAX: C2RustUnnamed = 11;
pub const CTRL_CMD_GETPOLICY: C2RustUnnamed = 10;
pub const CTRL_CMD_GETMCAST_GRP: C2RustUnnamed = 9;
pub const CTRL_CMD_DELMCAST_GRP: C2RustUnnamed = 8;
pub const CTRL_CMD_NEWMCAST_GRP: C2RustUnnamed = 7;
pub const CTRL_CMD_GETOPS: C2RustUnnamed = 6;
pub const CTRL_CMD_DELOPS: C2RustUnnamed = 5;
pub const CTRL_CMD_NEWOPS: C2RustUnnamed = 4;
pub const CTRL_CMD_GETFAMILY: C2RustUnnamed = 3;
pub const CTRL_CMD_DELFAMILY: C2RustUnnamed = 2;
pub const CTRL_CMD_NEWFAMILY: C2RustUnnamed = 1;
pub const CTRL_CMD_UNSPEC: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const __CTRL_ATTR_MAX: C2RustUnnamed_0 = 11;
pub const CTRL_ATTR_OP: C2RustUnnamed_0 = 10;
pub const CTRL_ATTR_OP_POLICY: C2RustUnnamed_0 = 9;
pub const CTRL_ATTR_POLICY: C2RustUnnamed_0 = 8;
pub const CTRL_ATTR_MCAST_GROUPS: C2RustUnnamed_0 = 7;
pub const CTRL_ATTR_OPS: C2RustUnnamed_0 = 6;
pub const CTRL_ATTR_MAXATTR: C2RustUnnamed_0 = 5;
pub const CTRL_ATTR_HDRSIZE: C2RustUnnamed_0 = 4;
pub const CTRL_ATTR_VERSION: C2RustUnnamed_0 = 3;
pub const CTRL_ATTR_FAMILY_NAME: C2RustUnnamed_0 = 2;
pub const CTRL_ATTR_FAMILY_ID: C2RustUnnamed_0 = 1;
pub const CTRL_ATTR_UNSPEC: C2RustUnnamed_0 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct taskstats {
    pub version: __u16,
    pub ac_exitcode: __u32,
    pub ac_flag: __u8,
    pub ac_nice: __u8,
    pub cpu_count: __u64,
    pub cpu_delay_total: __u64,
    pub blkio_count: __u64,
    pub blkio_delay_total: __u64,
    pub swapin_count: __u64,
    pub swapin_delay_total: __u64,
    pub cpu_run_real_total: __u64,
    pub cpu_run_virtual_total: __u64,
    pub ac_comm: [libc::c_char; 32],
    pub ac_sched: __u8,
    pub ac_pad: [__u8; 3],
    pub ac_uid: __u32,
    pub ac_gid: __u32,
    pub ac_pid: __u32,
    pub ac_ppid: __u32,
    pub ac_btime: __u32,
    pub ac_etime: __u64,
    pub ac_utime: __u64,
    pub ac_stime: __u64,
    pub ac_minflt: __u64,
    pub ac_majflt: __u64,
    pub coremem: __u64,
    pub virtmem: __u64,
    pub hiwater_rss: __u64,
    pub hiwater_vm: __u64,
    pub read_char: __u64,
    pub write_char: __u64,
    pub read_syscalls: __u64,
    pub write_syscalls: __u64,
    pub read_bytes: __u64,
    pub write_bytes: __u64,
    pub cancelled_write_bytes: __u64,
    pub nvcsw: __u64,
    pub nivcsw: __u64,
    pub ac_utimescaled: __u64,
    pub ac_stimescaled: __u64,
    pub cpu_scaled_run_real_total: __u64,
    pub freepages_count: __u64,
    pub freepages_delay_total: __u64,
    pub thrashing_count: __u64,
    pub thrashing_delay_total: __u64,
    pub ac_btime64: __u64,
    pub compact_count: __u64,
    pub compact_delay_total: __u64,
    pub ac_tgid: __u32,
    pub ac_tgetime: __u64,
    pub ac_exe_dev: __u64,
    pub ac_exe_inode: __u64,
    pub wpcopy_count: __u64,
    pub wpcopy_delay_total: __u64,
}
pub type C2RustUnnamed_1 = libc::c_uint;
pub const __TASKSTATS_CMD_MAX: C2RustUnnamed_1 = 3;
pub const TASKSTATS_CMD_NEW: C2RustUnnamed_1 = 2;
pub const TASKSTATS_CMD_GET: C2RustUnnamed_1 = 1;
pub const TASKSTATS_CMD_UNSPEC: C2RustUnnamed_1 = 0;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const __TASKSTATS_TYPE_MAX: C2RustUnnamed_2 = 7;
pub const TASKSTATS_TYPE_NULL: C2RustUnnamed_2 = 6;
pub const TASKSTATS_TYPE_AGGR_TGID: C2RustUnnamed_2 = 5;
pub const TASKSTATS_TYPE_AGGR_PID: C2RustUnnamed_2 = 4;
pub const TASKSTATS_TYPE_STATS: C2RustUnnamed_2 = 3;
pub const TASKSTATS_TYPE_TGID: C2RustUnnamed_2 = 2;
pub const TASKSTATS_TYPE_PID: C2RustUnnamed_2 = 1;
pub const TASKSTATS_TYPE_UNSPEC: C2RustUnnamed_2 = 0;
pub type C2RustUnnamed_3 = libc::c_uint;
pub const __TASKSTATS_CMD_ATTR_MAX: C2RustUnnamed_3 = 5;
pub const TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK: C2RustUnnamed_3 = 4;
pub const TASKSTATS_CMD_ATTR_REGISTER_CPUMASK: C2RustUnnamed_3 = 3;
pub const TASKSTATS_CMD_ATTR_TGID: C2RustUnnamed_3 = 2;
pub const TASKSTATS_CMD_ATTR_PID: C2RustUnnamed_3 = 1;
pub const TASKSTATS_CMD_ATTR_UNSPEC: C2RustUnnamed_3 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cgroupstats {
    pub nr_sleeping: __u64,
    pub nr_running: __u64,
    pub nr_stopped: __u64,
    pub nr_uninterruptible: __u64,
    pub nr_io_wait: __u64,
}
pub type C2RustUnnamed_4 = libc::c_uint;
pub const __CGROUPSTATS_CMD_MAX: C2RustUnnamed_4 = 6;
pub const CGROUPSTATS_CMD_NEW: C2RustUnnamed_4 = 5;
pub const CGROUPSTATS_CMD_GET: C2RustUnnamed_4 = 4;
pub const CGROUPSTATS_CMD_UNSPEC: C2RustUnnamed_4 = 3;
pub type C2RustUnnamed_5 = libc::c_uint;
pub const __CGROUPSTATS_TYPE_MAX: C2RustUnnamed_5 = 2;
pub const CGROUPSTATS_TYPE_CGROUP_STATS: C2RustUnnamed_5 = 1;
pub const CGROUPSTATS_TYPE_UNSPEC: C2RustUnnamed_5 = 0;
pub type C2RustUnnamed_6 = libc::c_uint;
pub const __CGROUPSTATS_CMD_ATTR_MAX: C2RustUnnamed_6 = 2;
pub const CGROUPSTATS_CMD_ATTR_FD: C2RustUnnamed_6 = 1;
pub const CGROUPSTATS_CMD_ATTR_UNSPEC: C2RustUnnamed_6 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct msgtemplate {
    pub n: nlmsghdr,
    pub g: genlmsghdr,
    pub buf: [libc::c_char; 1024],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub n: nlmsghdr,
    pub g: genlmsghdr,
    pub buf: [libc::c_char; 256],
}
#[no_mangle]
pub static mut rcvbufsz: libc::c_int = 0;
#[no_mangle]
pub static mut name: [libc::c_char; 100] = [0; 100];
#[no_mangle]
pub static mut dbg: libc::c_int = 0;
#[no_mangle]
pub static mut print_delays: libc::c_int = 0;
#[no_mangle]
pub static mut print_io_accounting: libc::c_int = 0;
#[no_mangle]
pub static mut print_task_context_switch_counts: libc::c_int = 0;
#[no_mangle]
pub static mut cpumask: [libc::c_char; 292] = [0; 292];
unsafe extern "C" fn usage() {
    fprintf(
        stderr,
        b"getdelays [-dilv] [-w logfile] [-r bufsize] [-m cpumask] [-t tgid] [-p pid]\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        stderr,
        b"  -d: print delayacct stats\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        stderr,
        b"  -i: print IO accounting (works only with -p)\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(stderr, b"  -l: listen forever\n\0" as *const u8 as *const libc::c_char);
    fprintf(stderr, b"  -v: debug on\n\0" as *const u8 as *const libc::c_char);
    fprintf(stderr, b"  -C: container path\n\0" as *const u8 as *const libc::c_char);
}

fn create_nl_socket_rs() -> Socket {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();

    // TODO: Set RCVBUF

    let addr = socket.bind_auto().unwrap();
    println!("socket port number = {}", addr.port_number());

    socket
}
unsafe extern "C" fn create_nl_socket(mut protocol: libc::c_int) -> libc::c_int {
    let mut current_block: u64;
    let mut fd: libc::c_int = 0;
    let mut local: sockaddr_nl = sockaddr_nl {
        nl_family: 0,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    fd = socket(16 as libc::c_int, SOCK_RAW as libc::c_int, protocol);
    if fd < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if rcvbufsz != 0 {
        if setsockopt(
            fd,
            1 as libc::c_int,
            8 as libc::c_int,
            &mut rcvbufsz as *mut libc::c_int as *const libc::c_void,
            ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
        ) < 0 as libc::c_int
        {
            fprintf(
                stderr,
                b"Unable to set socket rcv buf size to %d\n\0" as *const u8
                    as *const libc::c_char,
                rcvbufsz,
            );
            current_block = 10619232472088905366;
        } else {
            current_block = 15240798224410183470;
        }
    } else {
        current_block = 15240798224410183470;
    }
    match current_block {
        15240798224410183470 => {
            memset(
                &mut local as *mut sockaddr_nl as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<sockaddr_nl>() as libc::c_ulong,
            );
            local.nl_family = 16 as libc::c_int as __kernel_sa_family_t;
            if !(bind(
                fd,
                &mut local as *mut sockaddr_nl as *mut sockaddr,
                ::core::mem::size_of::<sockaddr_nl>() as libc::c_ulong as socklen_t,
            ) < 0 as libc::c_int)
            {
                return fd;
            }
        }
        _ => {}
    }
    close(fd);
    return -(1 as libc::c_int);
}

fn send_cmd_rs<T: NetlinkSerializable>(socket: &Socket, nlmsg_type: u16, nlmsg_pid: u32, payload: NetlinkPayload<T>) {
    let mut netlink_message = NetlinkMessage::new(
        NetlinkHeader::default(), payload
    );
    // TODO: netlink_message.header.length 
    netlink_message.header.message_type = nlmsg_type;
    netlink_message.header.flags = NLM_F_REQUEST;
    netlink_message.header.sequence_number = 0;
    netlink_message.header.port_number = nlmsg_pid;
    netlink_message.finalize();

    let mut buf = Vec::with_capacity(netlink_message.buffer_len());
    netlink_message.serialize(&mut buf[..]);

    let mut sent = 0;
    while sent < buf.len() {
        let r = socket.send_to(&buf[sent..], &SocketAddr::new(0, 0), 0).unwrap();
        if r > 0 {
            sent += r;
        } else {
            panic!("send failed");
        }
    }
}
unsafe extern "C" fn send_cmd(
    mut sd: libc::c_int,
    mut nlmsg_type: __u16,
    mut nlmsg_pid: __u32,
    mut genl_cmd: __u8,
    mut nla_type: __u16,
    mut nla_data: *mut libc::c_void,
    mut nla_len: libc::c_int,
) -> libc::c_int {
    let mut na: *mut nlattr = 0 as *mut nlattr;
    let mut nladdr: sockaddr_nl = sockaddr_nl {
        nl_family: 0,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let mut r: libc::c_int = 0;
    let mut buflen: libc::c_int = 0;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut msg: msgtemplate = msgtemplate {
        n: nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: 0,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        },
        g: genlmsghdr {
            cmd: 0,
            version: 0,
            reserved: 0,
        },
        buf: [0; 1024],
    };
    msg
        .n
        .nlmsg_len = ((::core::mem::size_of::<genlmsghdr>() as libc::c_ulong)
        .wrapping_add(4 as libc::c_uint as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        & !(4 as libc::c_uint).wrapping_sub(1 as libc::c_int as libc::c_uint)
            as libc::c_ulong)
        .wrapping_add(
            ((::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                & !(4 as libc::c_uint).wrapping_sub(1 as libc::c_int as libc::c_uint)
                    as libc::c_ulong) as libc::c_int as libc::c_ulong,
        ) as __u32;
    msg.n.nlmsg_type = nlmsg_type;
    msg.n.nlmsg_flags = 0x1 as libc::c_int as __u16;
    msg.n.nlmsg_seq = 0 as libc::c_int as __u32;
    msg.n.nlmsg_pid = nlmsg_pid;
    msg.g.cmd = genl_cmd;
    msg.g.version = 0x1 as libc::c_int as __u8;
    na = ((&mut msg as *mut msgtemplate as *mut libc::c_char)
        .offset(
            ((::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                & !(4 as libc::c_uint).wrapping_sub(1 as libc::c_int as libc::c_uint)
                    as libc::c_ulong) as libc::c_int as isize,
        ) as *mut libc::c_void)
        .offset(
            ((::core::mem::size_of::<genlmsghdr>() as libc::c_ulong)
                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                & !(4 as libc::c_uint).wrapping_sub(1 as libc::c_int as libc::c_uint)
                    as libc::c_ulong) as isize,
        ) as *mut nlattr;
    (*na).nla_type = nla_type;
    (*na)
        .nla_len = (nla_len
        + ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
            .wrapping_add(4 as libc::c_int as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong) as libc::c_int)
        as __u16;
    memcpy(
        (na as *mut libc::c_char)
            .offset(
                ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                    .wrapping_add(4 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_void,
        nla_data,
        nla_len as libc::c_ulong,
    );
    msg
        .n
        .nlmsg_len = (msg.n.nlmsg_len as libc::c_uint)
        .wrapping_add(
            ((*na).nla_len as libc::c_uint)
                .wrapping_add(4 as libc::c_uint)
                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                & !(4 as libc::c_uint).wrapping_sub(1 as libc::c_int as libc::c_uint),
        ) as __u32 as __u32;
    buf = &mut msg as *mut msgtemplate as *mut libc::c_char;
    buflen = msg.n.nlmsg_len as libc::c_int;
    memset(
        &mut nladdr as *mut sockaddr_nl as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_nl>() as libc::c_ulong,
    );
    nladdr.nl_family = 16 as libc::c_int as __kernel_sa_family_t;
    loop {
        r = sendto(
            sd,
            buf as *const libc::c_void,
            buflen as size_t,
            0 as libc::c_int,
            &mut nladdr as *mut sockaddr_nl as *mut sockaddr,
            ::core::mem::size_of::<sockaddr_nl>() as libc::c_ulong as socklen_t,
        ) as libc::c_int;
        if !(r < buflen) {
            break;
        }
        if r > 0 as libc::c_int {
            buf = buf.offset(r as isize);
            buflen -= r;
        } else if *__errno_location() != 11 as libc::c_int {
            return -(1 as libc::c_int)
        }
    }
    return 0 as libc::c_int;
}
const TASKSTATS_GENL_NAME: &str = "TASKSTATS";

fn get_family_id_rs(socket: &Socket) -> u16 {
    let mut genlmsg = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(TASKSTATS_GENL_NAME.to_string())]
    });
    genlmsg.finalize();
    let r = send_cmd_rs(socket, GENL_ID_CTRL, std::process::id(), NetlinkPayload::from(genlmsg));

    let mut rxbuf = vec![0u8; 4096];
    let rep_len = socket.recv(&mut rxbuf, 0).unwrap();

    let msg = <NetlinkMessage<GenlMessage<GenlCtrl>>>::deserialize(&rxbuf).unwrap();

    let id = match msg.payload {
        NetlinkPayload::InnerMessage(genlmsg) => {
            if GenlCtrlCmd::NewFamily == genlmsg.payload.cmd {
                let family_id = genlmsg.payload.nlas.iter().find_map(|nla| {
                    match nla {
                        GenlCtrlAttrs::FamilyId(id) => Some(*id),
                        _ => None
                    }
                }).unwrap();
                println!("family_id = {}", family_id);
                family_id
            } else {
                panic!("unexpected response");
            }
        }
        NetlinkPayload::Error(err) => {
            panic!("Received a netlink error message: {err:?}");
        }
        _ => {
            panic!("unexpected response");
        }
    };

    id
}
unsafe extern "C" fn get_family_id(mut sd: libc::c_int) -> libc::c_int {
    let mut ans: C2RustUnnamed_7 = C2RustUnnamed_7 {
        n: nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: 0,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        },
        g: genlmsghdr {
            cmd: 0,
            version: 0,
            reserved: 0,
        },
        buf: [0; 256],
    };
    let mut id: libc::c_int = 0 as libc::c_int;
    let mut rc: libc::c_int = 0;
    let mut na: *mut nlattr = 0 as *mut nlattr;
    let mut rep_len: libc::c_int = 0;
    strcpy(name.as_mut_ptr(), b"TASKSTATS\0" as *const u8 as *const libc::c_char);
    rc = send_cmd(
        sd,
        0x10 as libc::c_int as __u16,
        getpid() as __u32,
        CTRL_CMD_GETFAMILY as libc::c_int as __u8,
        CTRL_ATTR_FAMILY_NAME as libc::c_int as __u16,
        name.as_mut_ptr() as *mut libc::c_void,
        (strlen(b"TASKSTATS\0" as *const u8 as *const libc::c_char))
            .wrapping_add(1 as libc::c_int as libc::c_ulong) as libc::c_int,
    );
    if rc < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    rep_len = recv(
        sd,
        &mut ans as *mut C2RustUnnamed_7 as *mut libc::c_void,
        ::core::mem::size_of::<C2RustUnnamed_7>() as libc::c_ulong,
        0 as libc::c_int,
    ) as libc::c_int;
    if ans.n.nlmsg_type as libc::c_int == 0x2 as libc::c_int
        || rep_len < 0 as libc::c_int
        || !(rep_len
            >= ::core::mem::size_of::<nlmsghdr>() as libc::c_ulong as libc::c_int
            && ans.n.nlmsg_len as libc::c_ulong
                >= ::core::mem::size_of::<nlmsghdr>() as libc::c_ulong
            && ans.n.nlmsg_len <= rep_len as libc::c_uint)
    {
        return 0 as libc::c_int;
    }
    na = ((&mut ans as *mut C2RustUnnamed_7 as *mut libc::c_char)
        .offset(
            ((::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                & !(4 as libc::c_uint).wrapping_sub(1 as libc::c_int as libc::c_uint)
                    as libc::c_ulong) as libc::c_int as isize,
        ) as *mut libc::c_void)
        .offset(
            ((::core::mem::size_of::<genlmsghdr>() as libc::c_ulong)
                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                & !(4 as libc::c_uint).wrapping_sub(1 as libc::c_int as libc::c_uint)
                    as libc::c_ulong) as isize,
        ) as *mut nlattr;
    na = (na as *mut libc::c_char)
        .offset(
            ((*na).nla_len as libc::c_int + 4 as libc::c_int - 1 as libc::c_int
                & !(4 as libc::c_int - 1 as libc::c_int)) as isize,
        ) as *mut nlattr;
    if (*na).nla_type as libc::c_int == CTRL_ATTR_FAMILY_ID as libc::c_int {
        id = *((na as *mut libc::c_char)
            .offset(
                ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                    .wrapping_add(4 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_void as *mut __u16) as libc::c_int;
    }
    return id;
}
unsafe extern "C" fn print_delayacct(mut t: *mut taskstats) {
    printf(
        b"\n\nCPU   %15s%15s%15s%15s%15s\n      %15llu%15llu%15llu%15llu%15.3fms\nIO    %15s%15s%15s\n      %15llu%15llu%15llums\nSWAP  %15s%15s%15s\n      %15llu%15llu%15llums\nRECLAIM  %12s%15s%15s\n      %15llu%15llu%15llums\nTHRASHING%12s%15s%15s\n      %15llu%15llu%15llums\nCOMPACT  %12s%15s%15s\n      %15llu%15llu%15llums\nWPCOPY   %12s%15s%15s\n      %15llu%15llu%15llums\n\0"
            as *const u8 as *const libc::c_char,
        b"count\0" as *const u8 as *const libc::c_char,
        b"real total\0" as *const u8 as *const libc::c_char,
        b"virtual total\0" as *const u8 as *const libc::c_char,
        b"delay total\0" as *const u8 as *const libc::c_char,
        b"delay average\0" as *const u8 as *const libc::c_char,
        (*t).cpu_count,
        (*t).cpu_run_real_total,
        (*t).cpu_run_virtual_total,
        (*t).cpu_delay_total,
        (*t).cpu_delay_total as libc::c_double
            / 1000000 as libc::c_ulonglong as libc::c_double
            / (if (*t).cpu_count != 0 {
                (*t).cpu_count
            } else {
                1 as libc::c_int as libc::c_ulonglong
            }) as libc::c_double,
        b"count\0" as *const u8 as *const libc::c_char,
        b"delay total\0" as *const u8 as *const libc::c_char,
        b"delay average\0" as *const u8 as *const libc::c_char,
        (*t).blkio_count,
        (*t).blkio_delay_total,
        ((*t).blkio_delay_total)
            .wrapping_div(1000000 as libc::c_ulonglong)
            .wrapping_div(
                (if (*t).blkio_count != 0 {
                    (*t).blkio_count
                } else {
                    1 as libc::c_int as libc::c_ulonglong
                }),
            ),
        b"count\0" as *const u8 as *const libc::c_char,
        b"delay total\0" as *const u8 as *const libc::c_char,
        b"delay average\0" as *const u8 as *const libc::c_char,
        (*t).swapin_count,
        (*t).swapin_delay_total,
        ((*t).swapin_delay_total)
            .wrapping_div(1000000 as libc::c_ulonglong)
            .wrapping_div(
                (if (*t).swapin_count != 0 {
                    (*t).swapin_count
                } else {
                    1 as libc::c_int as libc::c_ulonglong
                }),
            ),
        b"count\0" as *const u8 as *const libc::c_char,
        b"delay total\0" as *const u8 as *const libc::c_char,
        b"delay average\0" as *const u8 as *const libc::c_char,
        (*t).freepages_count,
        (*t).freepages_delay_total,
        ((*t).freepages_delay_total)
            .wrapping_div(1000000 as libc::c_ulonglong)
            .wrapping_div(
                (if (*t).freepages_count != 0 {
                    (*t).freepages_count
                } else {
                    1 as libc::c_int as libc::c_ulonglong
                }),
            ),
        b"count\0" as *const u8 as *const libc::c_char,
        b"delay total\0" as *const u8 as *const libc::c_char,
        b"delay average\0" as *const u8 as *const libc::c_char,
        (*t).thrashing_count,
        (*t).thrashing_delay_total,
        ((*t).thrashing_delay_total)
            .wrapping_div(1000000 as libc::c_ulonglong)
            .wrapping_div(
                (if (*t).thrashing_count != 0 {
                    (*t).thrashing_count
                } else {
                    1 as libc::c_int as libc::c_ulonglong
                }),
            ),
        b"count\0" as *const u8 as *const libc::c_char,
        b"delay total\0" as *const u8 as *const libc::c_char,
        b"delay average\0" as *const u8 as *const libc::c_char,
        (*t).compact_count,
        (*t).compact_delay_total,
        ((*t).compact_delay_total)
            .wrapping_div(1000000 as libc::c_ulonglong)
            .wrapping_div(
                (if (*t).compact_count != 0 {
                    (*t).compact_count
                } else {
                    1 as libc::c_int as libc::c_ulonglong
                }),
            ),
        b"count\0" as *const u8 as *const libc::c_char,
        b"delay total\0" as *const u8 as *const libc::c_char,
        b"delay average\0" as *const u8 as *const libc::c_char,
        (*t).wpcopy_count,
        (*t).wpcopy_delay_total,
        ((*t).wpcopy_delay_total)
            .wrapping_div(1000000 as libc::c_ulonglong)
            .wrapping_div(
                (if (*t).wpcopy_count != 0 {
                    (*t).wpcopy_count
                } else {
                    1 as libc::c_int as libc::c_ulonglong
                }),
            ),
    );
}
unsafe extern "C" fn task_context_switch_counts(mut t: *mut taskstats) {
    printf(
        b"\n\nTask   %15s%15s\n       %15llu%15llu\n\0" as *const u8
            as *const libc::c_char,
        b"voluntary\0" as *const u8 as *const libc::c_char,
        b"nonvoluntary\0" as *const u8 as *const libc::c_char,
        (*t).nvcsw,
        (*t).nivcsw,
    );
}
unsafe extern "C" fn print_cgroupstats(mut c: *mut cgroupstats) {
    printf(
        b"sleeping %llu, blocked %llu, running %llu, stopped %llu, uninterruptible %llu\n\0"
            as *const u8 as *const libc::c_char,
        (*c).nr_sleeping,
        (*c).nr_io_wait,
        (*c).nr_running,
        (*c).nr_stopped,
        (*c).nr_uninterruptible,
    );
}
unsafe extern "C" fn print_ioacct(mut t: *mut taskstats) {
    printf(
        b"%s: read=%llu, write=%llu, cancelled_write=%llu\n\0" as *const u8
            as *const libc::c_char,
        ((*t).ac_comm).as_mut_ptr(),
        (*t).read_bytes,
        (*t).write_bytes,
        (*t).cancelled_write_bytes,
    );
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut c: libc::c_int = 0;
    let mut rc: libc::c_int = 0;
    let mut rep_len: libc::c_int = 0;
    let mut aggr_len: libc::c_int = 0;
    let mut len2: libc::c_int = 0;
    let mut cmd_type: libc::c_int = TASKSTATS_CMD_ATTR_UNSPEC as libc::c_int;
    let mut id: __u16 = 0;
    let mut mypid: __u32 = 0;
    let mut na: *mut nlattr = 0 as *mut nlattr;
    let mut nl_sd: libc::c_int = -(1 as libc::c_int);
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut tid: pid_t = 0 as libc::c_int;
    let mut rtid: pid_t = 0 as libc::c_int;
    let mut fd: libc::c_int = 0 as libc::c_int;
    let mut write_file: libc::c_int = 0 as libc::c_int;
    let mut maskset: libc::c_int = 0 as libc::c_int;
    let mut logfile: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut loop_0: libc::c_int = 0 as libc::c_int;
    let mut containerset: libc::c_int = 0 as libc::c_int;
    let mut containerpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cfd: libc::c_int = 0 as libc::c_int;
    let mut forking: libc::c_int = 0 as libc::c_int;
    let mut sigset: sigset_t = sigset_t { __val: [0; 16] };
    let mut msg: msgtemplate = msgtemplate {
        n: nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: 0,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        },
        g: genlmsghdr {
            cmd: 0,
            version: 0,
            reserved: 0,
        },
        buf: [0; 1024],
    };
    while forking == 0 {
        c = getopt(
            argc,
            argv as *const *mut libc::c_char,
            b"qdiw:r:m:t:p:vlC:c:\0" as *const u8 as *const libc::c_char,
        );
        if c < 0 as libc::c_int {
            break;
        }
        match c {
            100 => {
                printf(
                    b"print delayacct stats ON\n\0" as *const u8 as *const libc::c_char,
                );
                print_delays = 1 as libc::c_int;
            }
            105 => {
                printf(
                    b"printing IO accounting\n\0" as *const u8 as *const libc::c_char,
                );
                print_io_accounting = 1 as libc::c_int;
            }
            113 => {
                printf(
                    b"printing task/process context switch rates\n\0" as *const u8
                        as *const libc::c_char,
                );
                print_task_context_switch_counts = 1 as libc::c_int;
            }
            67 => {
                containerset = 1 as libc::c_int;
                containerpath = optarg;
            }
            119 => {
                logfile = strdup(optarg);
                printf(
                    b"write to file %s\n\0" as *const u8 as *const libc::c_char,
                    logfile,
                );
                write_file = 1 as libc::c_int;
            }
            114 => {
                rcvbufsz = atoi(optarg);
                printf(
                    b"receive buf size %d\n\0" as *const u8 as *const libc::c_char,
                    rcvbufsz,
                );
                if rcvbufsz < 0 as libc::c_int {
                    fprintf(
                        stderr,
                        b"Invalid rcv buf size\n\0" as *const u8 as *const libc::c_char,
                    );
                    exit(1 as libc::c_int);
                }
            }
            109 => {
                strncpy(
                    cpumask.as_mut_ptr(),
                    optarg,
                    ::core::mem::size_of::<[libc::c_char; 292]>() as libc::c_ulong,
                );
                cpumask[(::core::mem::size_of::<[libc::c_char; 292]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    as usize] = '\0' as i32 as libc::c_char;
                maskset = 1 as libc::c_int;
                printf(
                    b"cpumask %s maskset %d\n\0" as *const u8 as *const libc::c_char,
                    cpumask.as_mut_ptr(),
                    maskset,
                );
            }
            116 => {
                tid = atoi(optarg);
                if tid == 0 {
                    fprintf(
                        stderr,
                        b"Invalid tgid\n\0" as *const u8 as *const libc::c_char,
                    );
                    exit(1 as libc::c_int);
                }
                cmd_type = TASKSTATS_CMD_ATTR_TGID as libc::c_int;
            }
            112 => {
                tid = atoi(optarg);
                if tid == 0 {
                    fprintf(
                        stderr,
                        b"Invalid pid\n\0" as *const u8 as *const libc::c_char,
                    );
                    exit(1 as libc::c_int);
                }
                cmd_type = TASKSTATS_CMD_ATTR_PID as libc::c_int;
            }
            99 => {
                if sigemptyset(&mut sigset) == -(1 as libc::c_int) {
                    fprintf(
                        stderr,
                        b"Failed to empty sigset\0" as *const u8 as *const libc::c_char,
                    );
                    exit(1 as libc::c_int);
                }
                if sigaddset(&mut sigset, 17 as libc::c_int) != 0 {
                    fprintf(
                        stderr,
                        b"Failed to set sigchld in sigset\0" as *const u8
                            as *const libc::c_char,
                    );
                    exit(1 as libc::c_int);
                }
                sigprocmask(0 as libc::c_int, &mut sigset, 0 as *mut sigset_t);
                tid = fork();
                if tid < 0 as libc::c_int {
                    fprintf(
                        stderr,
                        b"Fork failed\n\0" as *const u8 as *const libc::c_char,
                    );
                    exit(1 as libc::c_int);
                }
                if tid == 0 as libc::c_int {
                    if execvp(
                        *argv.offset((optind - 1 as libc::c_int) as isize),
                        &mut *argv.offset((optind - 1 as libc::c_int) as isize)
                            as *mut *mut libc::c_char as *const *mut libc::c_char,
                    ) < 0 as libc::c_int
                    {
                        exit(-(1 as libc::c_int));
                    }
                }
                cmd_type = TASKSTATS_CMD_ATTR_PID as libc::c_int;
                forking = 1 as libc::c_int;
            }
            118 => {
                printf(b"debug on\n\0" as *const u8 as *const libc::c_char);
                dbg = 1 as libc::c_int;
            }
            108 => {
                printf(b"listen forever\n\0" as *const u8 as *const libc::c_char);
                loop_0 = 1 as libc::c_int;
            }
            _ => {
                usage();
                exit(-(1 as libc::c_int));
            }
        }
    }
    if write_file != 0 {
        fd = open(
            logfile,
            0o1 as libc::c_int | 0o100 as libc::c_int | 0o1000 as libc::c_int,
            0o400 as libc::c_int | 0o200 as libc::c_int
                | 0o400 as libc::c_int >> 3 as libc::c_int
                | 0o400 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int,
        );
        if fd == -(1 as libc::c_int) {
            perror(b"Cannot open output file\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
    }
    nl_sd = create_nl_socket(16 as libc::c_int);
    if nl_sd < 0 as libc::c_int {
        fprintf(
            stderr,
            b"error creating Netlink socket\n\0" as *const u8 as *const libc::c_char,
        );
        exit(1 as libc::c_int);
    }
    mypid = getpid() as __u32;
    id = get_family_id(nl_sd) as __u16;
    if id == 0 {
        fprintf(
            stderr,
            b"Error getting family id, errno %d\n\0" as *const u8 as *const libc::c_char,
            *__errno_location(),
        );
    } else {
        if dbg != 0 {
            printf(
                b"family id %d\n\0" as *const u8 as *const libc::c_char,
                id as libc::c_int,
            );
        }
        if maskset != 0 {
            rc = send_cmd(
                nl_sd,
                id,
                mypid,
                TASKSTATS_CMD_GET as libc::c_int as __u8,
                TASKSTATS_CMD_ATTR_REGISTER_CPUMASK as libc::c_int as __u16,
                &mut cpumask as *mut [libc::c_char; 292] as *mut libc::c_void,
                (strlen(cpumask.as_mut_ptr()))
                    .wrapping_add(1 as libc::c_int as libc::c_ulong) as libc::c_int,
            );
            if dbg != 0 {
                printf(
                    b"Sent register cpumask, retval %d\n\0" as *const u8
                        as *const libc::c_char,
                    rc,
                );
            }
            if rc < 0 as libc::c_int {
                fprintf(
                    stderr,
                    b"error sending register cpumask\n\0" as *const u8
                        as *const libc::c_char,
                );
                current_block = 16831393923422054882;
            } else {
                current_block = 16791665189521845338;
            }
        } else {
            current_block = 16791665189521845338;
        }
        match current_block {
            16831393923422054882 => {}
            _ => {
                if tid != 0 && containerset != 0 {
                    fprintf(
                        stderr,
                        b"Select either -t or -C, not both\n\0" as *const u8
                            as *const libc::c_char,
                    );
                } else {
                    if tid != 0 && forking != 0 {
                        let mut sig_received: libc::c_int = 0;
                        sigwait(&mut sigset, &mut sig_received);
                    }
                    if tid != 0 {
                        rc = send_cmd(
                            nl_sd,
                            id,
                            mypid,
                            TASKSTATS_CMD_GET as libc::c_int as __u8,
                            cmd_type as __u16,
                            &mut tid as *mut pid_t as *mut libc::c_void,
                            ::core::mem::size_of::<__u32>() as libc::c_ulong
                                as libc::c_int,
                        );
                        if dbg != 0 {
                            printf(
                                b"Sent pid/tgid, retval %d\n\0" as *const u8
                                    as *const libc::c_char,
                                rc,
                            );
                        }
                        if rc < 0 as libc::c_int {
                            fprintf(
                                stderr,
                                b"error sending tid/tgid cmd\n\0" as *const u8
                                    as *const libc::c_char,
                            );
                            current_block = 6109666272876517348;
                        } else {
                            current_block = 13003737910779602957;
                        }
                    } else {
                        current_block = 13003737910779602957;
                    }
                    match current_block {
                        13003737910779602957 => {
                            if containerset != 0 {
                                cfd = open(containerpath, 0 as libc::c_int);
                                if cfd < 0 as libc::c_int {
                                    perror(
                                        b"error opening container file\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    current_block = 16831393923422054882;
                                } else {
                                    rc = send_cmd(
                                        nl_sd,
                                        id,
                                        mypid,
                                        CGROUPSTATS_CMD_GET as libc::c_int as __u8,
                                        CGROUPSTATS_CMD_ATTR_FD as libc::c_int as __u16,
                                        &mut cfd as *mut libc::c_int as *mut libc::c_void,
                                        ::core::mem::size_of::<__u32>() as libc::c_ulong
                                            as libc::c_int,
                                    );
                                    if rc < 0 as libc::c_int {
                                        perror(
                                            b"error sending cgroupstats command\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        current_block = 16831393923422054882;
                                    } else {
                                        current_block = 4983594971376015098;
                                    }
                                }
                            } else {
                                current_block = 4983594971376015098;
                            }
                            match current_block {
                                16831393923422054882 => {}
                                _ => {
                                    if maskset == 0 && tid == 0 && containerset == 0 {
                                        usage();
                                        current_block = 16831393923422054882;
                                    } else {
                                        's_556: loop {
                                            rep_len = recv(
                                                nl_sd,
                                                &mut msg as *mut msgtemplate as *mut libc::c_void,
                                                ::core::mem::size_of::<msgtemplate>() as libc::c_ulong,
                                                0 as libc::c_int,
                                            ) as libc::c_int;
                                            if dbg != 0 {
                                                printf(
                                                    b"received %d bytes\n\0" as *const u8
                                                        as *const libc::c_char,
                                                    rep_len,
                                                );
                                            }
                                            if rep_len < 0 as libc::c_int {
                                                fprintf(
                                                    stderr,
                                                    b"nonfatal reply error: errno %d\n\0" as *const u8
                                                        as *const libc::c_char,
                                                    *__errno_location(),
                                                );
                                            } else if msg.n.nlmsg_type as libc::c_int
                                                == 0x2 as libc::c_int
                                                || !(rep_len
                                                    >= ::core::mem::size_of::<nlmsghdr>() as libc::c_ulong
                                                        as libc::c_int
                                                    && msg.n.nlmsg_len as libc::c_ulong
                                                        >= ::core::mem::size_of::<nlmsghdr>() as libc::c_ulong
                                                    && msg.n.nlmsg_len <= rep_len as libc::c_uint)
                                            {
                                                let mut err: *mut nlmsgerr = (&mut msg as *mut msgtemplate
                                                    as *mut libc::c_char)
                                                    .offset(
                                                        ((::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
                                                            .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                            & !(4 as libc::c_uint)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                                as libc::c_ulong) as libc::c_int as isize,
                                                    ) as *mut libc::c_void as *mut nlmsgerr;
                                                fprintf(
                                                    stderr,
                                                    b"fatal reply error,  errno %d\n\0" as *const u8
                                                        as *const libc::c_char,
                                                    (*err).error,
                                                );
                                                break;
                                            } else {
                                                if dbg != 0 {
                                                    printf(
                                                        b"nlmsghdr size=%zu, nlmsg_len=%d, rep_len=%d\n\0"
                                                            as *const u8 as *const libc::c_char,
                                                        ::core::mem::size_of::<nlmsghdr>() as libc::c_ulong,
                                                        msg.n.nlmsg_len,
                                                        rep_len,
                                                    );
                                                }
                                                rep_len = ((msg.n.nlmsg_len)
                                                    .wrapping_sub(
                                                        ((0 as libc::c_int
                                                            + ((::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
                                                                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                & !(4 as libc::c_uint)
                                                                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                                    as libc::c_ulong) as libc::c_int) as libc::c_uint)
                                                            .wrapping_add(4 as libc::c_uint)
                                                            .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                            & !(4 as libc::c_uint)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_uint),
                                                    ) as libc::c_ulong)
                                                    .wrapping_sub(
                                                        (::core::mem::size_of::<genlmsghdr>() as libc::c_ulong)
                                                            .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                            & !(4 as libc::c_uint)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                                as libc::c_ulong,
                                                    ) as libc::c_int;
                                                na = ((&mut msg as *mut msgtemplate as *mut libc::c_char)
                                                    .offset(
                                                        ((::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
                                                            .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                            & !(4 as libc::c_uint)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                                as libc::c_ulong) as libc::c_int as isize,
                                                    ) as *mut libc::c_void)
                                                    .offset(
                                                        ((::core::mem::size_of::<genlmsghdr>() as libc::c_ulong)
                                                            .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                            & !(4 as libc::c_uint)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                                as libc::c_ulong) as isize,
                                                    ) as *mut nlattr;
                                                len = 0 as libc::c_int;
                                                while len < rep_len {
                                                    len
                                                        += (*na).nla_len as libc::c_int + 4 as libc::c_int
                                                            - 1 as libc::c_int & !(4 as libc::c_int - 1 as libc::c_int);
                                                    match (*na).nla_type as libc::c_int {
                                                        5 | 4 => {
                                                            aggr_len = (*na).nla_len as libc::c_int
                                                                - ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                    .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                    & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                    as libc::c_int;
                                                            len2 = 0 as libc::c_int;
                                                            na = (na as *mut libc::c_char)
                                                                .offset(
                                                                    ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                        .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                        & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                        as libc::c_int as isize,
                                                                ) as *mut libc::c_void as *mut nlattr;
                                                            while len2 < aggr_len {
                                                                match (*na).nla_type as libc::c_int {
                                                                    1 => {
                                                                        rtid = *((na as *mut libc::c_char)
                                                                            .offset(
                                                                                ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                                    .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                                    & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                                    as libc::c_int as isize,
                                                                            ) as *mut libc::c_void as *mut libc::c_int);
                                                                        if print_delays != 0 {
                                                                            printf(
                                                                                b"PID\t%d\n\0" as *const u8 as *const libc::c_char,
                                                                                rtid,
                                                                            );
                                                                        }
                                                                    }
                                                                    2 => {
                                                                        rtid = *((na as *mut libc::c_char)
                                                                            .offset(
                                                                                ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                                    .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                                    & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                                    as libc::c_int as isize,
                                                                            ) as *mut libc::c_void as *mut libc::c_int);
                                                                        if print_delays != 0 {
                                                                            printf(
                                                                                b"TGID\t%d\n\0" as *const u8 as *const libc::c_char,
                                                                                rtid,
                                                                            );
                                                                        }
                                                                    }
                                                                    3 => {
                                                                        if print_delays != 0 {
                                                                            print_delayacct(
                                                                                (na as *mut libc::c_char)
                                                                                    .offset(
                                                                                        ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                                            .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                                            & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                                            as libc::c_int as isize,
                                                                                    ) as *mut libc::c_void as *mut taskstats,
                                                                            );
                                                                        }
                                                                        if print_io_accounting != 0 {
                                                                            print_ioacct(
                                                                                (na as *mut libc::c_char)
                                                                                    .offset(
                                                                                        ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                                            .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                                            & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                                            as libc::c_int as isize,
                                                                                    ) as *mut libc::c_void as *mut taskstats,
                                                                            );
                                                                        }
                                                                        if print_task_context_switch_counts != 0 {
                                                                            task_context_switch_counts(
                                                                                (na as *mut libc::c_char)
                                                                                    .offset(
                                                                                        ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                                            .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                                            & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                                            as libc::c_int as isize,
                                                                                    ) as *mut libc::c_void as *mut taskstats,
                                                                            );
                                                                        }
                                                                        if fd != 0 {
                                                                            if write(
                                                                                fd,
                                                                                (na as *mut libc::c_char)
                                                                                    .offset(
                                                                                        ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                                            .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                                            & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                                            as libc::c_int as isize,
                                                                                    ) as *mut libc::c_void,
                                                                                (*na).nla_len as size_t,
                                                                            ) < 0 as libc::c_int as libc::c_long
                                                                            {
                                                                                fprintf(
                                                                                    stderr,
                                                                                    b"write error\n\0" as *const u8 as *const libc::c_char,
                                                                                );
                                                                                exit(1 as libc::c_int);
                                                                            }
                                                                        }
                                                                        if loop_0 == 0 {
                                                                            break 's_556;
                                                                        }
                                                                    }
                                                                    6 => {}
                                                                    _ => {
                                                                        fprintf(
                                                                            stderr,
                                                                            b"Unknown nested nla_type %d\n\0" as *const u8
                                                                                as *const libc::c_char,
                                                                            (*na).nla_type as libc::c_int,
                                                                        );
                                                                    }
                                                                }
                                                                len2
                                                                    += (*na).nla_len as libc::c_int + 4 as libc::c_int
                                                                        - 1 as libc::c_int & !(4 as libc::c_int - 1 as libc::c_int);
                                                                na = (na as *mut libc::c_char)
                                                                    .offset(
                                                                        ((*na).nla_len as libc::c_int + 4 as libc::c_int
                                                                            - 1 as libc::c_int & !(4 as libc::c_int - 1 as libc::c_int))
                                                                            as isize,
                                                                    ) as *mut nlattr;
                                                            }
                                                        }
                                                        1 => {
                                                            print_cgroupstats(
                                                                (na as *mut libc::c_char)
                                                                    .offset(
                                                                        ((::core::mem::size_of::<nlattr>() as libc::c_ulong)
                                                                            .wrapping_add(4 as libc::c_int as libc::c_ulong)
                                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                            & !(4 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                                                                            as libc::c_int as isize,
                                                                    ) as *mut libc::c_void as *mut cgroupstats,
                                                            );
                                                        }
                                                        6 => {}
                                                        _ => {
                                                            fprintf(
                                                                stderr,
                                                                b"Unknown nla_type %d\n\0" as *const u8
                                                                    as *const libc::c_char,
                                                                (*na).nla_type as libc::c_int,
                                                            );
                                                        }
                                                    }
                                                    na = ((&mut msg as *mut msgtemplate as *mut libc::c_char)
                                                        .offset(
                                                            ((::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
                                                                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                & !(4 as libc::c_uint)
                                                                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                                    as libc::c_ulong) as libc::c_int as isize,
                                                        ) as *mut libc::c_void)
                                                        .offset(
                                                            ((::core::mem::size_of::<genlmsghdr>() as libc::c_ulong)
                                                                .wrapping_add(4 as libc::c_uint as libc::c_ulong)
                                                                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                                & !(4 as libc::c_uint)
                                                                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                                                    as libc::c_ulong) as isize,
                                                        )
                                                        .offset(len as isize) as *mut nlattr;
                                                }
                                            }
                                            if !(loop_0 != 0) {
                                                break;
                                            }
                                        }
                                        current_block = 6109666272876517348;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    match current_block {
                        16831393923422054882 => {}
                        _ => {
                            if maskset != 0 {
                                rc = send_cmd(
                                    nl_sd,
                                    id,
                                    mypid,
                                    TASKSTATS_CMD_GET as libc::c_int as __u8,
                                    TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK as libc::c_int
                                        as __u16,
                                    &mut cpumask as *mut [libc::c_char; 292]
                                        as *mut libc::c_void,
                                    (strlen(cpumask.as_mut_ptr()))
                                        .wrapping_add(1 as libc::c_int as libc::c_ulong)
                                        as libc::c_int,
                                );
                                printf(
                                    b"Sent deregister mask, retval %d\n\0" as *const u8
                                        as *const libc::c_char,
                                    rc,
                                );
                                if rc < 0 as libc::c_int {
                                    fprintf(
                                        stderr,
                                        b"error sending deregister cpumask\n\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    exit(rc);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    close(nl_sd);
    if fd != 0 {
        close(fd);
    }
    if cfd != 0 {
        close(cfd);
    }
    return 0 as libc::c_int;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
