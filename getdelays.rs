use clap::{arg, Parser};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_GENERIC};
use netlink_packet_core::{NetlinkMessage, NetlinkHeader, NetlinkPayload, constants::{NLM_F_REQUEST}, NetlinkSerializable};
use netlink_packet_generic::{constants::{GENL_HDRLEN, GENL_ID_CTRL}, GenlMessage, ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs}};

mod taskstats_packet;
use taskstats_packet::{TaskstatsCmd, TaskstatsCmdAttrs, TaskstatsCtrl};

use crate::taskstats_packet::{Taskstats, TaskstatsTypeAttrs};
use log::{debug, info, warn, error};

fn create_nl_socket() -> Socket {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();

    // TODO: Set RCVBUF

    let addr = socket.bind_auto().unwrap();

    socket
}
fn send_cmd<T: NetlinkSerializable + std::fmt::Debug>(socket: &Socket, nlmsg_type: u16, nlmsg_pid: u32, payload: NetlinkPayload<T>) {
    let mut netlink_message = NetlinkMessage::new(
        NetlinkHeader::default(), payload
    );
    // TODO: netlink_message.header.length 
    // netlink_message.header.length = 123;
    netlink_message.header.message_type = nlmsg_type;
    netlink_message.header.flags = NLM_F_REQUEST;
    netlink_message.header.sequence_number = 0;
    netlink_message.header.port_number = nlmsg_pid;
    netlink_message.finalize();

    let mut buf = vec![0u8; netlink_message.buffer_len()];
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
const TASKSTATS_GENL_NAME: &str = "TASKSTATS";

fn get_family_id(socket: &Socket) -> u16 {
    let mut genlmsg = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(TASKSTATS_GENL_NAME.to_string())]
    });
    genlmsg.finalize();
    send_cmd(socket, GENL_ID_CTRL, std::process::id(), NetlinkPayload::from(genlmsg));

    let mut rxbuf = vec![0; 4096];
    let rep_len = socket.recv(&mut &mut rxbuf[..], 0).unwrap();

    let msg = <NetlinkMessage<GenlMessage<GenlCtrl>>>::deserialize(&rxbuf[0..rep_len]).unwrap();

    let id = match msg.payload {
        NetlinkPayload::InnerMessage(genlmsg) => {
            if GenlCtrlCmd::NewFamily == genlmsg.payload.cmd {
                let family_id = genlmsg.payload.nlas.iter().find_map(|nla| {
                    match nla {
                        GenlCtrlAttrs::FamilyId(id) => Some(*id),
                        _ => None
                    }
                }).unwrap();
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

fn average_ms_f64(total: u64, count: u64) -> f64 {
    total as f64 / 1000000.0 / (
        if count != 0 {
            count
        } else {
            1
        }
    ) as f64
}
fn average_ms_u64(total: u64, count: u64) -> u64 {
    total / 1000000 / (
        if count != 0 {
            count
        } else {
            1
        }
    )
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
    println!(
        "\n\nTask   {:>15}{:>15}",
        "voluntary", "nonvoluntary"
    );
    println!(
        "       {:>15}{:>15}",
        t.nvcsw, t.nivcsw
    );
}
fn print_ioacct(t: &Taskstats) {
    println!(
        "{}: read={} write={} cancelled_write={}",
        String::from_utf8_lossy(&t.ac_comm),
        t.read_bytes, t.write_bytes, t.cancelled_write_bytes
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


pub fn main() {
    pretty_env_logger::init();
    let args = Args::parse();

    let socket = create_nl_socket();
    let family_id = get_family_id(&socket);
    
    if family_id == 0 {
        error!("Error getting family id, errno");
        return;
    }
    debug!("family id {}", family_id);

    if args.pid != 0 {
        let mut genlmsg = GenlMessage::from_payload(TaskstatsCtrl {
            cmd: TaskstatsCmd::Get,
            nlas: vec![TaskstatsCmdAttrs::Pid(args.pid)]
        });
        genlmsg.set_resolved_family_id(family_id);
        genlmsg.finalize();
        send_cmd(&socket, family_id, std::process::id(), NetlinkPayload::from(genlmsg));

        debug!("Sent pid/tgid");
    }

    let mut rxbuf = vec![0; 4096];
    let rep_len =  socket.recv(&mut &mut rxbuf[..], 0).unwrap();

    debug!("received {} bytes", rep_len);

    let response = <NetlinkMessage<GenlMessage<TaskstatsCtrl<TaskstatsTypeAttrs>>>>::deserialize(&rxbuf[0..(rep_len as usize)]).unwrap();


    match response.payload {
        NetlinkPayload::Error(err) => {
            debug!("fatal reply error: {}", err);
            return;
        },
        NetlinkPayload::InnerMessage(genlmsg) => {
            for nla in genlmsg.payload.nlas.iter() {
                match nla {
                    TaskstatsTypeAttrs::Pid(rtid) => {
                        if args.print_delays {
                            println!("PID\t{}", rtid);
                        }
                    },
                    TaskstatsTypeAttrs::Tgid(rtid) => {
                        if args.print_delays {
                            println!("TGID\t{}", rtid);
                        }
                    },
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
                    },
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
                    },
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
                    },
                    _ => {}
                }
            }
        }
        _ => {

        }
    }

}
