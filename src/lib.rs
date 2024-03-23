use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_REQUEST};
use netlink_packet_generic::{constants::GENL_ID_CTRL, ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd}, GenlMessage};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};
use anyhow::{anyhow, Context, Result};

use crate::taskstats::{TaskstatsCmd, TaskstatsCmdAttrs, TaskstatsCtrl};

pub mod taskstats;

pub fn create_nl_socket() -> Result<Socket> {
    let mut socket = Socket::new(NETLINK_GENERIC)?;
    socket.bind_auto()?;

    Ok(socket)
}
pub fn send_cmd<T: NetlinkSerializable + std::fmt::Debug>(
    socket: &Socket,
    nlmsg_type: u16,
    nlmsg_pid: u32,
    payload: NetlinkPayload<T>,
) -> Result<()> {
    let mut netlink_message = NetlinkMessage::new(NetlinkHeader::default(), payload);
    netlink_message.header.message_type = nlmsg_type;
    netlink_message.header.flags = NLM_F_REQUEST;
    netlink_message.header.sequence_number = 0;
    netlink_message.header.port_number = nlmsg_pid;
    netlink_message.finalize();

    let mut buf = vec![0u8; netlink_message.buffer_len()];
    netlink_message.serialize(&mut buf[..]);

    let mut sent = 0;
    while sent < buf.len() {
        let r = socket.send_to(&buf[sent..], &SocketAddr::new(0, 0), 0)?;
        if r > 0 {
            sent += r;
        } else {
            return Err(anyhow!("failed to send packet to netlink socket"));
        }
    }
    Ok(())
}
pub const TASKSTATS_GENL_NAME: &str = "TASKSTATS";

pub fn get_family_id(socket: &Socket) -> Result<u16> {
    let mut genlmsg = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(TASKSTATS_GENL_NAME.to_string())],
    });
    genlmsg.finalize();
    send_cmd(
        socket,
        GENL_ID_CTRL,
        std::process::id(),
        NetlinkPayload::from(genlmsg),
    )?;

    let mut rxbuf = vec![0; 4096];
    let rep_len = socket.recv(&mut &mut rxbuf[..], 0)?;

    let msg = <NetlinkMessage<GenlMessage<GenlCtrl>>>::deserialize(&rxbuf[0..rep_len])?;

    if let NetlinkPayload::InnerMessage(genlmsg) = msg.payload {
        if GenlCtrlCmd::NewFamily == genlmsg.payload.cmd {
            return genlmsg
                .payload
                .nlas
                .iter()
                .find_map(|nla| match nla {
                    GenlCtrlAttrs::FamilyId(id) => Some(*id),
                    _ => None,
                })
                .ok_or(anyhow!("family id not found"));
        }
    }

    Err(anyhow!("unexpected response"))
}

pub fn send_delay_request(socket: &Socket, family_id: u16, pid: u32) -> Result<()> {
    let mut genlmsg = GenlMessage::from_payload(TaskstatsCtrl {
        cmd: TaskstatsCmd::Get,
        nlas: vec![TaskstatsCmdAttrs::Pid(pid)],
    });
    genlmsg.set_resolved_family_id(family_id);
    genlmsg.finalize();
    send_cmd(
        socket,
        family_id,
        std::process::id(),
        NetlinkPayload::from(genlmsg),
    )
    .context("error sending tid/tgid cmd")
}
