use std::mem::size_of;

use anyhow::{bail, Context, Result};
use clap::{arg, Parser};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;

use getdelays_rs::{
    create_nl_socket, get_family_id, send_delay_request,
    taskstats::{Taskstats, TaskstatsCtrl, TaskstatsTypeAttrs},
};

use log::*;

fn average_ms_f64(total: u64, count: u64) -> f64 {
    total as f64 / 1000000.0 / (if count != 0 { count } else { 1 }) as f64
}
fn average_ms_u64(total: u64, count: u64) -> u64 {
    total / 1000000 / (if count != 0 { count } else { 1 })
}

fn print_delayacct(t: &Taskstats) {
    println!(
        "CPU   {:>15}{:>15}{:>15}{:>15}{:>15}",
        "count", "real total", "virtual total", "delay total", "delay average"
    );
    println!(
        "      {:>15}{:>15}{:>15}{:>15}{:>15.3}ms",
        t.cpu_count,
        t.cpu_run_real_total,
        t.cpu_run_virtual_total,
        t.cpu_delay_total,
        average_ms_f64(t.cpu_delay_total, t.cpu_count)
    );
    println!(
        "IO    {:>15}{:>15}{:>15}",
        "count", "delay total", "delay average"
    );
    println!(
        "      {:>15}{:>15}{:>15}ms",
        t.blkio_count,
        t.blkio_delay_total,
        average_ms_u64(t.blkio_delay_total, t.blkio_count)
    );
    println!(
        "SWAP  {:>15}{:>15}{:>15}",
        "count", "delay total", "delay average"
    );
    println!(
        "      {:>15}{:>15}{:>15}ms",
        t.swapin_count,
        t.swapin_delay_total,
        average_ms_u64(t.swapin_delay_total, t.swapin_count)
    );
    println!(
        "RECLAIM  {:>12}{:>15}{:>15}",
        "count", "delay total", "delay average"
    );
    println!(
        "      {:>15}{:>15}{:>15}ms",
        t.freepages_count,
        t.freepages_delay_total,
        average_ms_u64(t.freepages_delay_total, t.freepages_count)
    );
    println!(
        "THRASHING{:>12}{:>15}{:>15}",
        "count", "delay total", "delay average"
    );
    println!(
        "      {:>15}{:>15}{:>15}ms",
        t.thrashing_count,
        t.thrashing_delay_total,
        average_ms_u64(t.thrashing_delay_total, t.thrashing_count)
    );
    println!(
        "COMPACT  {:>12}{:>15}{:>15}",
        "count", "delay total", "delay average"
    );
    println!(
        "      {:>15}{:>15}{:>15}ms",
        t.compact_count,
        t.compact_delay_total,
        average_ms_u64(t.compact_delay_total, t.compact_count)
    );
    println!(
        "WPCOPY   {:>12}{:>15}{:>15}",
        "count", "delay total", "delay average"
    );
    println!(
        "      {:>15}{:>15}{:>15}ms",
        t.wpcopy_count,
        t.wpcopy_delay_total,
        average_ms_u64(t.wpcopy_delay_total, t.wpcopy_count)
    );
}
fn task_context_switch_counts(t: &Taskstats) {
    println!("\n\nTask   {:>15}{:>15}", "voluntary", "nonvoluntary");
    println!("       {:>15}{:>15}", t.nvcsw, t.nivcsw);
}
fn print_ioacct(t: &Taskstats) {
    println!(
        "{}: read={} write={} cancelled_write={}",
        String::from_utf8_lossy(&t.ac_comm),
        t.read_bytes,
        t.write_bytes,
        t.cancelled_write_bytes
    );
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short = 'd')]
    print_delays: bool,

    #[arg(short = 'i')]
    print_io_accounting: bool,

    #[arg(short = 'q')]
    print_task_context_switch_counts: bool,

    #[arg(short = 'p')]
    pid: u32,
}

pub fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();
    if args.print_delays {
        println!("print delayacct stats ON");
    }
    if args.print_io_accounting {
        println!("printing IO accounting");
    }
    if args.print_task_context_switch_counts {
        println!("printing task/process context switch rates");
    }
    if args.pid == 0 {
        bail!("Invalid pid");
    }

    let socket = create_nl_socket().context("error creating Netlink socket")?;
    let family_id = get_family_id(&socket).context("Error getting family id")?;

    if family_id == 0 {
        bail!("Error getting family id");
    }
    debug!("family id {}", family_id);

    if args.pid != 0 {
        send_delay_request(&socket, family_id, args.pid)?;
        debug!("Sent pid/tgid, retval 0");
    }

    let mut rxbuf = vec![0; 4096];
    let rep_len = socket
        .recv(&mut &mut rxbuf[..], 0)
        .context("nonfatal reply error")?; // TODO: handle nonfatal reply error
    debug!("received {} bytes", rep_len);

    let response = <NetlinkMessage<GenlMessage<TaskstatsCtrl<TaskstatsTypeAttrs>>>>::deserialize(
        &rxbuf[0..(rep_len as usize)],
    )
    .context("fatal reply error: unable to parse Netlink Packet")?;
    debug!(
        "nlmsghdr size={}, nlmsg_len={}, rep_len={}",
        size_of::<NetlinkHeader>(),
        response.buffer_len(),
        rep_len
    );

    match response.payload {
        NetlinkPayload::Error(err) => {
            bail!("fatal reply error: {}", err);
        }
        NetlinkPayload::InnerMessage(genlmsg) => {
            for nla in genlmsg.payload.nlas.iter() {
                match nla {
                    TaskstatsTypeAttrs::Pid(rtid) => {
                        if args.print_delays {
                            println!("PID\t{}", rtid);
                        }
                    }
                    TaskstatsTypeAttrs::Tgid(rtid) => {
                        if args.print_delays {
                            println!("TGID\t{}", rtid);
                        }
                    }
                    TaskstatsTypeAttrs::Stats(stats) => {
                        if args.print_delays {
                            print_delayacct(stats);
                        }
                        if args.print_io_accounting {
                            print_ioacct(stats);
                        }
                        if args.print_task_context_switch_counts {
                            task_context_switch_counts(stats);
                        }
                    }
                    TaskstatsTypeAttrs::AggrPid(rtid, stats) => {
                        if args.print_delays {
                            println!("PID\t{}", rtid);
                            print_delayacct(stats);
                        }
                        if args.print_io_accounting {
                            print_ioacct(stats);
                        }
                        if args.print_task_context_switch_counts {
                            task_context_switch_counts(stats);
                        }
                    }
                    TaskstatsTypeAttrs::AggrTgid(rtid, stats) => {
                        if args.print_delays {
                            println!("PID\t{}", rtid);
                            print_delayacct(stats);
                        }
                        if args.print_io_accounting {
                            print_ioacct(stats);
                        }
                        if args.print_task_context_switch_counts {
                            task_context_switch_counts(stats);
                        }
                    }
                    TaskstatsTypeAttrs::Null => {}
                    _ => {
                        warn!("Unknown nla_type {:?}", nla);
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}
