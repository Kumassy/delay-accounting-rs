use anyhow::{bail, Context, Result};
use clap::Parser;
use getdelays_rs::{
    create_nl_socket, get_family_id, send_delay_request,
    taskstats::{Taskstats, TaskstatsCtrl, TaskstatsTypeAttrs},
};
use lazy_static::lazy_static;
use log::*;
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use prometheus_exporter::prometheus::{register_int_gauge_vec, IntGaugeVec};
use std::{ffi::CStr, mem::size_of, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};

fn update_metrics(stats: &Taskstats) {
    let comm = CStr::from_bytes_until_nul(&stats.ac_comm).map_or("".into(), CStr::to_string_lossy);
    let pid = stats.ac_pid;

    VERSION
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.version as i64);
    AT_EXITCODE
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_exitcode as i64);

    AC_FLAG
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_flag as i64);
    AC_NICE
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_nice as i64);

    CPU_COUNT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.cpu_count as i64);
    CPU_DELAY_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.cpu_delay_total as i64);

    BLKIO_COUNT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.blkio_count as i64);
    BLKIO_DELAY_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.blkio_delay_total as i64);

    SWAPIN_COUNT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.swapin_count as i64);
    SWAPIN_DELAY_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.swapin_delay_total as i64);

    CPU_RUN_REAL_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.cpu_run_real_total as i64);
    CPU_RUN_VIRTUAL_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.cpu_run_virtual_total as i64);

    AC_SCHED
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_sched as i64);
    AC_UID
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_uid as i64);
    AC_GID
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_gid as i64);
    AC_PID
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_pid as i64);
    AC_PPID
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_ppid as i64);
    AC_BTIME
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_btime as i64);
    AC_ETIME
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_etime as i64);
    AC_UTIME
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_utime as i64);
    AC_STIME
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_stime as i64);
    AC_MINFLT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_minflt as i64);
    AC_MAJFLT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_majflt as i64);

    COREMEM
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.coremem as i64);
    VIRTMEM
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.virtmem as i64);

    HIWATER_RSS
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.hiwater_rss as i64);
    HIWATER_VM
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.hiwater_vm as i64);

    READ_CHAR
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.read_char as i64);
    WRITE_CHAR
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.write_char as i64);
    READ_SYSCALLS
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.read_syscalls as i64);
    WRITE_SYSCALLS
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.write_syscalls as i64);

    READ_BYTES
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.read_bytes as i64);
    WRITE_BYTES
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.write_bytes as i64);
    CANCELLED_WRITE_BYTES
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.cancelled_write_bytes as i64);

    NVCSW
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.nvcsw as i64);
    NIVCSW
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.nivcsw as i64);

    AC_UTIMESCALED
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_utimescaled as i64);
    AC_STIMESCALED
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_stimescaled as i64);
    CPU_SCALED_RUN_REAL_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.cpu_scaled_run_real_total as i64);

    FREEPAGES_COUNT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.freepages_count as i64);
    FREEPAGES_DELAY_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.freepages_delay_total as i64);

    THRASHING_COUNT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.thrashing_count as i64);
    THRASHING_DELAY_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.thrashing_delay_total as i64);

    AC_BTIME64
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_btime64 as i64);

    COMPACT_COUNT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.compact_count as i64);
    COMPACT_DELAY_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.compact_delay_total as i64);

    AC_TGID
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_tgid as i64);

    AC_TGETIME
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_tgetime as i64);

    AC_EXE_DEV
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_exe_dev as i64);
    AC_EXE_INODE
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.ac_exe_inode as i64);

    WPCOPY_COUNT
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.wpcopy_count as i64);
    WPCOPY_DELAY_TOTAL
        .with_label_values(&[&pid.to_string(), &comm])
        .set(stats.wpcopy_delay_total as i64);

    IRQ_COUNT.with_label_values(&[&pid.to_string(), &comm]).set(stats.irq_count as i64);
    IRQ_DELAY_TOTAL.with_label_values(&[&pid.to_string(), &comm]).set(stats.irq_delay_total as i64);
}

lazy_static! {
    static ref VERSION: IntGaugeVec = register_int_gauge_vec!("delay_accounting_version", "The version number of this struct. This field is always set to TAKSTATS_VERSION, which is defined in <linux/taskstats.h>. Each time the struct is changed, the value should be incremented.", &["pid", "comm"]).unwrap();
    static ref AT_EXITCODE: IntGaugeVec = register_int_gauge_vec!("delay_accounting_at_exit_code", "Exit Status", &["pid", "comm"]).unwrap();

    static ref AC_FLAG: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_flag", "The accounting flags of a task as defined in <linux/acct.h> Defined values are AFORK, ASU, ACOMPAT, ACORE, AXSIG, and AGROUP. (AGROUP since version 12).", &["pid", "comm"]).unwrap();
    static ref AC_NICE: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_nice", "task_nice", &["pid", "comm"]).unwrap();

    static ref CPU_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_cpu_count", "Delay waiting for cpu, while runnable count, delay_total NOT updated atomically", &["pid", "comm"]).unwrap();
    static ref CPU_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_cpu_delay_total", "Delay waiting for cpu, while runnable count, delay_total NOT updated atomically", &["pid", "comm"]).unwrap();

    static ref BLKIO_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_blkio_count", "Delay waiting for synchronous block I/O to complete does not account for delays in I/O submission", &["pid", "comm"]).unwrap();
    static ref BLKIO_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_blkio_delay_total", "Delay waiting for synchronous block I/O to complete does not account for delays in I/O submission", &["pid", "comm"]).unwrap();

    static ref SWAPIN_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_swapin_count", "Delay waiting for page fault I/O (swap in only)", &["pid", "comm"]).unwrap();
    static ref SWAPIN_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_swapin_delay_total", "Delay waiting for page fault I/O (swap in only)", &["pid", "comm"]).unwrap();

    static ref CPU_RUN_REAL_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_cpu_run_real_total", "cpu \"wall-clock\" running time On some architectures, value will adjust for cpu time stolen from the kernel in involuntary waits due to virtualization. Value is cumulative, in nanoseconds, without a corresponding count and wraps around to zero silently on overflow", &["pid", "comm"]).unwrap();
    static ref CPU_RUN_VIRTUAL_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_cpu_run_virtual_total", "cpu \"virtual\" running time Uses time intervals seen by the kernel i.e. no adjustment for kernel's involuntary waits due to virtualization. Value is cumulative, in nanoseconds, without a corresponding count and wraps around to zero silently on overflow", &["pid", "comm"]).unwrap();

    static ref AC_SCHED: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_sched", "Scheduling discipline", &["pid", "comm"]).unwrap();
    static ref AC_UID: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_uid", "User ID", &["pid", "comm"]).unwrap();
    static ref AC_GID: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_gid", "Group ID", &["pid", "comm"]).unwrap();
    static ref AC_PID: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_pid", "Process ID", &["pid", "comm"]).unwrap();
    static ref AC_PPID: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_ppid", "Parent process ID", &["pid", "comm"]).unwrap();
    static ref AC_BTIME: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_btime", "Begin time [sec since 1970]", &["pid", "comm"]).unwrap();
    static ref AC_ETIME: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_etime", "Elapsed time [usec]", &["pid", "comm"]).unwrap();
    static ref AC_UTIME: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_utime", "User CPU time [usec]", &["pid", "comm"]).unwrap();
    static ref AC_STIME: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_stime", "SYstem CPU time [usec]", &["pid", "comm"]).unwrap();
    static ref AC_MINFLT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_minflt", "Minor Page Fault Count", &["pid", "comm"]).unwrap();
    static ref AC_MAJFLT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_majflt", "Major Page Fault Count", &["pid", "comm"]).unwrap();

    static ref COREMEM: IntGaugeVec = register_int_gauge_vec!("delay_accounting_coremem", "accumulated RSS usage in MB-usec. Accumulated RSS usage in duration of a task, in MBytes-usecs. The current rss usage is added to this counter every time a tick is charged to a task's system time. So, at the end we will have memory usage multiplied by system time. Thus an average usage per system time unit can be calculated.", &["pid", "comm"]).unwrap();
    static ref VIRTMEM: IntGaugeVec = register_int_gauge_vec!("delay_accounting_virtmem", "accumulated VM  usage in MB-usec. Accumulated virtual memory usage in duration of a task. Same as acct_rss_mem1 above except that we keep track of VM usage.", &["pid", "comm"]).unwrap();

    static ref HIWATER_RSS: IntGaugeVec = register_int_gauge_vec!("delay_accounting_hiwater_rss", "High-watermark of RSS usage, in KB", &["pid", "comm"]).unwrap();
    static ref HIWATER_VM: IntGaugeVec = register_int_gauge_vec!("delay_accounting_hiwater_vm", "High-water VM usage, in KB", &["pid", "comm"]).unwrap();

    static ref READ_CHAR: IntGaugeVec = register_int_gauge_vec!("delay_accounting_read_char", "bytes read", &["pid", "comm"]).unwrap();
    static ref WRITE_CHAR: IntGaugeVec = register_int_gauge_vec!("delay_accounting_write_char", "bytes written", &["pid", "comm"]).unwrap();
    static ref READ_SYSCALLS: IntGaugeVec = register_int_gauge_vec!("delay_accounting_read_syscalls", "read syscalls", &["pid", "comm"]).unwrap();
    static ref WRITE_SYSCALLS: IntGaugeVec = register_int_gauge_vec!("delay_accounting_write_syscalls", "write syscalls", &["pid", "comm"]).unwrap();

    static ref READ_BYTES: IntGaugeVec = register_int_gauge_vec!("delay_accounting_read_bytes", "bytes of read I/O", &["pid", "comm"]).unwrap();
    static ref WRITE_BYTES: IntGaugeVec = register_int_gauge_vec!("delay_accounting_write_bytes", "bytes of write I/O", &["pid", "comm"]).unwrap();
    static ref CANCELLED_WRITE_BYTES: IntGaugeVec = register_int_gauge_vec!("delay_accounting_cancelled_write_bytes", "bytes of cancelled write I/O", &["pid", "comm"]).unwrap();

    static ref NVCSW: IntGaugeVec = register_int_gauge_vec!("delay_accounting_nvcsw", "voluntary_ctxt_switches", &["pid", "comm"]).unwrap();
    static ref NIVCSW: IntGaugeVec = register_int_gauge_vec!("delay_accounting_nivcsw", "nonvoluntary_ctxt_switches", &["pid", "comm"]).unwrap();

    static ref AC_UTIMESCALED: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_utimescaled", "utime scaled on frequency etc", &["pid", "comm"]).unwrap();
    static ref AC_STIMESCALED: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_stimescaled", "stime scaled on frequency etc", &["pid", "comm"]).unwrap();
    static ref CPU_SCALED_RUN_REAL_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_cpu_scaled_run_real_total", "scaled cpu_run_real_total", &["pid", "comm"]).unwrap();

    static ref FREEPAGES_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_freepages_count", "Delay waiting for memory reclaim", &["pid", "comm"]).unwrap();
    static ref FREEPAGES_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_freepages_delay_total", "Delay waiting for memory reclaim", &["pid", "comm"]).unwrap();

    static ref THRASHING_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_thrashing_count", "HELP", &["pid", "comm"]).unwrap();
    static ref THRASHING_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_thrashing_delay_total", "HELP", &["pid", "comm"]).unwrap();

    static ref AC_BTIME64: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_btime64", "64-bit begin time", &["pid", "comm"]).unwrap();

    static ref COMPACT_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_compact_count", "Delay waiting for memory compact", &["pid", "comm"]).unwrap();
    static ref COMPACT_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_compact_delay_total", "Delay waiting for memory compact", &["pid", "comm"]).unwrap();

    static ref AC_TGID: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_tgid", "thread group ID", &["pid", "comm"]).unwrap();

    static ref AC_TGETIME: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_tgetime", "Thread group walltime up to now. This is total process walltime if AGROUP flag is set.", &["pid", "comm"]).unwrap();

    static ref AC_EXE_DEV: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_exe_dev", "program binary device ID. Lightweight information to identify process binary files. This leaves userspace to match this to a file system path, using MAJOR() and MINOR() macros to identify a device and mount point, the inode to identify the executable file. This is /proc/self/exe at the end, so matching the most recent exec(). Values are zero for kernel threads.", &["pid", "comm"]).unwrap();
    static ref AC_EXE_INODE: IntGaugeVec = register_int_gauge_vec!("delay_accounting_ac_exe_inode", "program binary inode number. Lightweight information to identify process binary files. This leaves userspace to match this to a file system path, using MAJOR() and MINOR() macros to identify a device and mount point, the inode to identify the executable file. This is /proc/self/exe at the end, so matching the most recent exec(). Values are zero for kernel threads.", &["pid", "comm"]).unwrap();

    static ref WPCOPY_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_wpcopy_count", "Delay waiting for write-protect copy", &["pid", "comm"]).unwrap();
    static ref WPCOPY_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_wpcopy_delay_total", "Delay waiting for write-protect copy", &["pid", "comm"]).unwrap();

    static ref IRQ_COUNT: IntGaugeVec = register_int_gauge_vec!("delay_accounting_irq_count", "Delay waiting for IRQ/SOFTIRQ", &["pid", "comm"]).unwrap();
    static ref IRQ_DELAY_TOTAL: IntGaugeVec = register_int_gauge_vec!("delay_accounting_irq_delay_total", "Delay waiting for IRQ/SOFTIRQ", &["pid", "comm"]).unwrap();
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short = 'i', long, default_value = "30", help = "interval in seconds to send delay request")]
    interval: u64,
    #[arg(short = 'p', long, default_value = "9186", help = "the port this exporter listens on")]
    port: u16,
}

fn main() -> Result<()> {
    pretty_env_logger::init_timed();
    let args = Args::parse();

    let socket = create_nl_socket().context("error creating Netlink socket")?;
    let socket = Arc::new(socket);
    let family_id = get_family_id(&socket).context("Error getting family id")?;

    if family_id == 0 {
        bail!("Error getting family id");
    }
    debug!("family id {}", family_id);

    let reader_socket = socket.clone();
    std::thread::spawn(move || loop {
        let mut rxbuf = vec![0; 4096];

        let rep_len = match reader_socket.recv(&mut &mut rxbuf[..], 0) {
            Ok(len) => len,
            Err(e) => {
                error!("failed to receive message {}", e);
                continue;
            }
        };
        debug!("received {} bytes", rep_len);

        let response =
            match <NetlinkMessage<GenlMessage<TaskstatsCtrl<TaskstatsTypeAttrs>>>>::deserialize(
                &rxbuf[0..(rep_len as usize)],
            ) {
                Ok(response) => response,
                Err(e) => {
                    error!("failed to deserialize message {}", e);
                    continue;
                }
            };
        debug!(
            "nlmsghdr size={}, nlmsg_len={}, rep_len={}",
            size_of::<NetlinkHeader>(),
            response.buffer_len(),
            rep_len
        );

        match response.payload {
            NetlinkPayload::Error(err) => {
                error!("fatal reply error: {}", err);
                return;
            }
            NetlinkPayload::Done(_) => {
                info!("closing socket");
                return;
            }
            NetlinkPayload::InnerMessage(genlmsg) => {
                for nla in genlmsg.payload.nlas.iter() {
                    match nla {
                        TaskstatsTypeAttrs::AggrPid(_rtid, stats)
                        | TaskstatsTypeAttrs::AggrTgid(_rtid, stats) => {
                            update_metrics(stats);
                        }
                        _ => {
                            warn!("Unknown nla_type {:?}", nla);
                        }
                    }
                }
            }
            _ => {}
        }
    });

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), args.port);
    let exporter = prometheus_exporter::start(addr).context("failed to start exporter")?;

    // list pids of all processes in the system
    loop {
        let _guard = exporter.wait_duration(std::time::Duration::from_secs(args.interval));

        let processes = procfs::process::all_processes().context("failed to list pids")?;
        for process in processes.flatten() {
            let pid = process.pid;
            debug!("send delay request for pid {}", pid);
            send_delay_request(&socket, family_id, pid as u32)?;
        }
    }
}
