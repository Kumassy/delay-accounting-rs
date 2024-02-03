use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{nla::{Nla, NlasIterator, NlaBuffer}, traits::*, DecodeError, parsers::{parse_u32, parse_string}};
use byteorder::{ByteOrder, NativeEndian};
use anyhow::Context;
use std::mem::size_of_val;

/// Command code definition of Taskstats family
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskstatsCmd {
    Unspec = 0,	/* Reserved */
	Get,		/* user->kernel request/get-response */
	New,		/* kernel->user event */
}

pub const TASKSTATS_CMD_NEW: u8 = 2;
pub const TASKSTATS_CMD_GET: u8 = 1;
pub const TASKSTATS_CMD_UNSPEC: u8 = 0;


impl From<TaskstatsCmd> for u8 {
    fn from(cmd: TaskstatsCmd) -> u8 {
        use TaskstatsCmd::*;
        match cmd {
            Unspec => TASKSTATS_CMD_UNSPEC,
            Get => TASKSTATS_CMD_GET,
            New => TASKSTATS_CMD_NEW,
        }
    }
}

impl TryFrom<u8> for TaskstatsCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use TaskstatsCmd::*;
        Ok(match value {
            TASKSTATS_CMD_UNSPEC => Unspec,
            TASKSTATS_CMD_GET => Get,
            TASKSTATS_CMD_NEW => New,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unknown control command: {cmd}"
                )))
            }
        })
    }
}

/// Payload of taskstats controller
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskstatsCtrl {
    /// Command code of this message
    pub cmd: TaskstatsCmd,
    /// Netlink attributes in this message
    pub nlas: Vec<TaskstatsCmdAttrs>,
}


impl GenlFamily for TaskstatsCtrl {
    fn family_name() -> &'static str {
        "TASKSTATS"
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        1
    }
}


impl Emitable for TaskstatsCtrl {
    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }
}


impl ParseableParametrized<[u8], GenlHeader> for TaskstatsCtrl {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            nlas: parse_ctrlnlas(buf)?,
        })
    }
}


fn parse_ctrlnlas(buf: &[u8]) -> Result<Vec<TaskstatsCmdAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| TaskstatsCmdAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse control message attributes")?;

    Ok(nlas)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskstatsCmdAttrs {
    Unspec,
    Pid(u32),
    Tgid(u32),
    // TODO: fix String doesn't compatible with UTF-8
    RegisterCpumask(String),
    // TODO: fix String doesn't compatible with UTF-8
    DeregisterCpumask(String),
}
pub const TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK: u16 = 4;
pub const TASKSTATS_CMD_ATTR_REGISTER_CPUMASK: u16 = 3;
pub const TASKSTATS_CMD_ATTR_TGID: u16 = 2;
pub const TASKSTATS_CMD_ATTR_PID: u16 = 1;
pub const TASKSTATS_CMD_ATTR_UNSPEC: u16 = 0;

impl Nla for TaskstatsCmdAttrs {
    fn value_len(&self) -> usize {
        use TaskstatsCmdAttrs::*;
        match self {
            Unspec => 0,
            Pid(v) => size_of_val(v),
            Tgid(v) => size_of_val(v),
            RegisterCpumask(s) => s.len() + 1,
            DeregisterCpumask(s) => s.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        use TaskstatsCmdAttrs::*;
        match self {
            Unspec => TASKSTATS_CMD_ATTR_UNSPEC,
            Pid(_) => TASKSTATS_CMD_ATTR_PID,
            Tgid(_) => TASKSTATS_CMD_ATTR_TGID,
            RegisterCpumask(_) => TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
            DeregisterCpumask(_) => TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use TaskstatsCmdAttrs::*;
        match self {
            Unspec => {},
            Pid(v) => NativeEndian::write_u32(buffer, *v),
            Tgid(v) => NativeEndian::write_u32(buffer, *v),
            RegisterCpumask(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            },
            DeregisterCpumask(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            },
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TaskstatsCmdAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_CMD_ATTR_UNSPEC => Self::Unspec,
            TASKSTATS_CMD_ATTR_PID => Self::Pid(
                parse_u32(payload)
                    .context("invalid TASKSTATS_CMD_ATTR_PID value")?,
            ),
            TASKSTATS_CMD_ATTR_TGID => Self::Tgid(
                parse_u32(payload)
                    .context("invalid TASKSTATS_CMD_ATTR_TGID value")?,
            ),
            TASKSTATS_CMD_ATTR_REGISTER_CPUMASK => Self::RegisterCpumask(
                parse_string(payload)
                    .context("invalid TASKSTATS_CMD_ATTR_REGISTER_CPUMASK value")?,
            ),
            TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK => Self::DeregisterCpumask(
                parse_string(payload)
                    .context("invalid TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK value")?,
            ),
            kind => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {kind}"
                )))
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskstatsTypeAttrs {
    Unspec,
    Pid(u32),
    Tgid(u32),
    Stats(Taskstats),
    AggrPid(u32, Taskstats),
    AggrTgid(u32, Taskstats),
    Null,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Taskstats {
    pub version: u16,
    pub ac_exitcode: u32,
    pub ac_flag: u8,
    pub ac_nice: u8,
    pub cpu_count: u64,
    // pub cpu_count: u64,
    pub cpu_delay_total: u64,
    pub blkio_count: u64,
    pub blkio_delay_total: u64,
    pub swapin_count: u64,
    pub swapin_delay_total: u64,
    pub cpu_run_real_total: u64,
    pub cpu_run_virtual_total: u64,
    pub ac_comm: [u8; 32], // TS_COMMON_LEN
    pub ac_sched: u8,
    // pub ac_sched: u8,
    pub ac_pad: [u8; 3],
    __pad: [u8; 4],
    pub ac_uid: u32,
    // pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,
    pub ac_etime: u64,
    // pub ac_etime: u64,
    pub ac_utime: u64,
    pub ac_stime: u64,
    pub ac_minflt: u64,
    pub ac_majflt: u64,
    pub coremem: u64,
    pub virtmem: u64,
    pub hiwater_rss: u64,
    pub hiwater_vm: u64,
    pub read_char: u64,
    pub write_char: u64,
    pub read_syscalls: u64,
    pub write_syscalls: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
    pub nvcsw: u64,
    pub nivcsw: u64,
    pub ac_utimescaled: u64,
    pub ac_stimescaled: u64,
    pub cpu_scaled_run_real_total: u64,
    pub freepages_count: u64,
    pub freepages_delay_total: u64,
    pub thrashing_count: u64,
    pub thrashing_delay_total: u64,
    pub ac_btime64: u64,
    pub compact_count: u64,
    pub compact_delay_total: u64,
    pub ac_tgid: u32,
    pub ac_tgetime: u64,
    pub ac_exe_dev: u64,
    pub ac_exe_inode: u64,
    pub wpcopy_count: u64,
    pub wpcopy_delay_total: u64,
}

pub const TASKSTATS_TYPE_NULL: u16 = 6;
pub const TASKSTATS_TYPE_AGGR_TGID: u16 = 5;
pub const TASKSTATS_TYPE_AGGR_PID: u16 = 4;
pub const TASKSTATS_TYPE_STATS: u16 = 3;
pub const TASKSTATS_TYPE_TGID: u16 = 2;
pub const TASKSTATS_TYPE_PID: u16 = 1;
pub const TASKSTATS_TYPE_UNSPEC: u16 = 0;



// impl Nla for TaskstatsTypeAttrs {
//     fn value_len(&self) -> usize {
//         use TaskstatsTypeAttrs::*;
//         match self {
//             Unspec => 0,
//             Pid(v) => size_of_val(v),
//             Tgid(v) => size_of_val(v),
//             Stats(s) => size_of_val(s),
//             AggrPid(v, s) => size_of_val(v) + size_of_val(s),
//             AggrTgid(v, s) => size_of_val(v) + size_of_val(s),
//             Null => 0,
//         }
//     }

//     fn kind(&self) -> u16 {
//         use TaskstatsTypeAttrs::*;
//         match self {
//             Unspec => TASKSTATS_TYPE_UNSPEC,
//             Pid(_) => TASKSTATS_TYPE_PID,
//             Tgid(_) => TASKSTATS_TYPE_TGID,
//             Stats(_) => TASKSTATS_TYPE_STATS,
//             AggrPid(_, _) => TASKSTATS_TYPE_AGGR_PID,
//             AggrTgid(_, _) => TASKSTATS_TYPE_AGGR_TGID,
//             Null => TASKSTATS_TYPE_NULL,
//         }
//     }

//     fn emit_value(&self, buffer: &mut [u8]) {
//         use TaskstatsTypeAttrs::*;
//         match self {
//             Unspec => {},
//             Pid(v) => NativeEndian::write_u32(buffer, *v),
//             Tgid(v) => NativeEndian::write_u32(buffer, *v),
//             Stats(s) => NativeEndian::write_u64(buffer, *s),
//             AggrPid(v, s) => {
//                 NativeEndian::write_u32(buffer, *v);
//                 NativeEndian::write_u64(&mut buffer[4..], *s);
//             },
//             AggrTgid(v, s) => {
//                 NativeEndian::write_u32(buffer, *v);
//                 NativeEndian::write_u64(&mut buffer[4..], *s);
//             },
//             Null => {},
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn test_parse_taskstats_type_pid() {
        let type_pid_bytes = [8, 0, 1, 0, 1, 0, 0, 0];
    }

    #[test]
    fn test_parse_taskstats_type_stats() {
        let type_stats_bytes = [0xa4, 1, 3, 0, 0xd, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 66, 8, 0, 0, 0, 0, 0, 0, 0xbf, 0x5e, 0xe7, 6, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0x8c, 51, 48, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xd9, 8, 4, 33, 0, 0, 0, 0, 0xc, 0xa1, 0x7a, 38, 0, 0, 0, 0, 73, 79, 73, 74, 65, 0x6d, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0xf2, 0x9b, 65, 0, 0, 0, 0, 0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, 44, 0x2c, 3, 0, 0, 0, 0, 0, 0x1a, 0xe3, 9, 0, 0, 0, 0, 0, 0x1b, 0x2a, 0, 0, 0, 0, 0, 0, 0xa2, 0, 0, 0, 0, 0, 0, 0, 11, 0xaa, 41, 0, 0, 0, 0, 0, 0xc3, 0xff, 64, 1, 0, 0, 0, 0, 0xd4, 28, 0, 0, 0, 0, 0, 0, 30, 0x8a, 3, 0, 0, 0, 0, 0, 0, 0xa0, 0xa, 0, 0, 0, 0, 0, 0, 74, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0xfc, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb9, 6, 0, 0, 0, 0, 0, 0, 0xb0, 1, 0, 0, 0, 0, 0, 0, 44, 0x2c, 3, 0, 0, 0, 0, 0, 0x1a, 0xe3, 9, 0, 0, 0, 0, 0, 0xd9, 8, 4, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0xf2, 0x9b, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, 1, 3, 1, 0, 0, 0, 0, 0, 0x6b, 0xd, 0, 0, 0, 0, 0, 0, 0x1c, 18, 0, 0, 0, 0, 0, 0, 13, 0xd8, 0xe4, 0, 0, 0, 0, 0];
    }

    #[test]
    fn test_parse_taskstats_type_agg_pid_stats() {
        let type_pid_stats_bytes = [0xb0, 1, 4, 0, 8, 0, 1, 0, 1, 0, 0, 0, 0xa4, 1, 3, 0, 0xd, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 66, 8, 0, 0, 0, 0, 0, 0, 0xbf, 0x5e, 0xe7, 6, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0x8c, 51, 48, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xd9, 8, 4, 33, 0, 0, 0, 0, 0xc, 0xa1, 0x7a, 38, 0, 0, 0, 0, 73, 79, 73, 74, 65, 0x6d, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0xf2, 0x9b, 65, 0, 0, 0, 0, 0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, 44, 0x2c, 3, 0, 0, 0, 0, 0, 0x1a, 0xe3, 9, 0, 0, 0, 0, 0, 0x1b, 0x2a, 0, 0, 0, 0, 0, 0, 0xa2, 0, 0, 0, 0, 0, 0, 0, 11, 0xaa, 41, 0, 0, 0, 0, 0, 0xc3, 0xff, 64, 1, 0, 0, 0, 0, 0xd4, 28, 0, 0, 0, 0, 0, 0, 30, 0x8a, 3, 0, 0, 0, 0, 0, 0, 0xa0, 0xa, 0, 0, 0, 0, 0, 0, 74, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0xfc, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb9, 6, 0, 0, 0, 0, 0, 0, 0xb0, 1, 0, 0, 0, 0, 0, 0, 44, 0x2c, 3, 0, 0, 0, 0, 0, 0x1a, 0xe3, 9, 0, 0, 0, 0, 0, 0xd9, 8, 4, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0xf2, 0x9b, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, 1, 3, 1, 0, 0, 0, 0, 0, 0x6b, 0xd, 0, 0, 0, 0, 0, 0, 0x1c, 18, 0, 0, 0, 0, 0, 0, 13, 0xd8, 0xe4, 0, 0, 0, 0, 0];

        // let nlas = parse_ctrlnlas(&bytes).unwrap();

        // assert_eq!(nlas.len(), 4);
        // assert_eq!(nlas[0], TaskstatsCmdAttrs::Pid(1));
        // assert_eq!(nlas[1], TaskstatsCmdAttrs::Tgid(2));
        // assert_eq!(nlas[2], TaskstatsCmdAttrs::RegisterCpumask(String::new()));
        // assert_eq!(nlas[3], TaskstatsCmdAttrs::DeregisterCpumask(String::new()));

    }
}