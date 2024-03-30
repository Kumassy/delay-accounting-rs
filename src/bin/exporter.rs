
use anyhow::{anyhow, bail, Context, Result};
use getdelays_rs::{create_nl_socket, get_family_id, print_delayacct, print_ioacct, send_delay_request, task_context_switch_counts, taskstats::{Taskstats, TaskstatsCtrl, TaskstatsTypeAttrs}};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_sys::Socket;
use std::{mem::size_of, net::SocketAddr, sync::Arc};
use prometheus_exporter::prometheus::{self, labels, register_gauge_vec};
use log::*;

fn main() -> Result<()> {
    pretty_env_logger::init();

    let socket = create_nl_socket().context("error creating Netlink socket")?;
    let socket = Arc::new(socket);
    let family_id = get_family_id(&socket).context("Error getting family id")?;

    if family_id == 0 {
        bail!("Error getting family id");
    }
    debug!("family id {}", family_id);

    let reader_socket = socket.clone();
    std::thread::spawn( move || {
        loop {
            let mut rxbuf = vec![0; 4096];

            let rep_len = reader_socket
                .recv(&mut &mut rxbuf[..], 0).unwrap();
            debug!("received {} bytes", rep_len);
    
            let response = <NetlinkMessage<GenlMessage<TaskstatsCtrl<TaskstatsTypeAttrs>>>>::deserialize(
                &rxbuf[0..(rep_len as usize)],
            )
            .context("fatal reply error: unable to parse Netlink Packet").unwrap();
            debug!(
                "nlmsghdr size={}, nlmsg_len={}, rep_len={}",
                size_of::<NetlinkHeader>(),
                response.buffer_len(),
                rep_len
            );
    
            match response.payload {
                NetlinkPayload::Error(err) => {
                    // bail!("fatal reply error: {}", err);
                }
                NetlinkPayload::InnerMessage(genlmsg) => {
                    for nla in genlmsg.payload.nlas.iter() {
                        match nla {
                            TaskstatsTypeAttrs::AggrPid(rtid, stats) | TaskstatsTypeAttrs::AggrTgid(rtid, stats) => {
                                print_delayacct(stats);
                                print_ioacct(stats);
                                task_context_switch_counts(stats);
                            }
                            _ => {
                                warn!("Unknown nla_type {:?}", nla);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });


    let addr: SocketAddr = "0.0.0.0:9186".parse()?;

    let gauge_vec = register_gauge_vec!("delay_accounting_cpu_usage", "CPU Usage of each process", &["pid", "comm"])?;
    let exporter = prometheus_exporter::start(addr)?;

    // list pids of all processes in the system
    loop {
        let _guard = exporter.wait_duration(std::time::Duration::from_secs(5));

        let pids = procfs::process::all_processes().context("failed to list pids")?;
        // iterate over all processes and collect their metrics
        for pid in pids {
            let pid = pid?.pid;
            let process = procfs::process::Process::new(pid).context("failed to get process")?;

            let cpu_usage = process.stat()?.utime + process.stat()?.stime;
            let memory_usage = process.stat()?.rss * procfs::page_size();

            gauge_vec.with_label_values(&[&pid.to_string(), &process.stat()?.comm]).set(cpu_usage as f64);

            debug!("send delay request for pid {}", pid);
            send_delay_request(&socket, family_id, pid as u32)?;
        }
    }

    Ok(())
}