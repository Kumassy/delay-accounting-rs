use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{nla::{Nla, NlasIterator, NlaBuffer}, traits::*, DecodeError, parsers::{parse_u32, parse_string}};
use byteorder::{ByteOrder, NativeEndian};
use anyhow::Context;
use std::mem::{size_of, size_of_val};

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
    RegisterCpumask(Vec<u8>),
    DeregisterCpumask(Vec<u8>),
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
            RegisterCpumask(v) => v.len(),
            DeregisterCpumask(v) => v.len(),
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
            RegisterCpumask(v) => {
                buffer[..v.len()].copy_from_slice(v);
            },
            DeregisterCpumask(v) => {
                buffer[..v.len()].copy_from_slice(v);
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
            TASKSTATS_CMD_ATTR_REGISTER_CPUMASK => {
                let bytes = payload.to_vec();
                Self::RegisterCpumask(bytes)
            },
            TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK => {
                let bytes = payload.to_vec();
                Self::DeregisterCpumask(bytes)
            },
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
    pub cpu_delay_total: u64,
    pub blkio_count: u64,
    pub blkio_delay_total: u64,
    pub swapin_count: u64,
    pub swapin_delay_total: u64,
    pub cpu_run_real_total: u64,
    pub cpu_run_virtual_total: u64,
    pub ac_comm: [u8; 32], // TS_COMMON_LEN
    pub ac_sched: u8,
    pub ac_pad: [u8; 3],
    __pad: [u8; 4],
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,
    pub ac_etime: u64,
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



impl Nla for TaskstatsTypeAttrs {
    fn value_len(&self) -> usize {
        use TaskstatsTypeAttrs::*;
        match self {
            Unspec => 0,
            Pid(v) => size_of_val(v),
            Tgid(v) => size_of_val(v),
            Stats(s) => size_of_val(s),
            AggrPid(v, s) => {
                let nla_pid = TaskstatsTypeAttrs::Pid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);

                nla_pid.buffer_len() + nla_stats.buffer_len()
            },
            AggrTgid(v, s) => {
                let nla_tgid = TaskstatsTypeAttrs::Tgid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);

                nla_tgid.buffer_len() + nla_stats.buffer_len()
            },
            Null => 0,
        }
    }

    fn kind(&self) -> u16 {
        use TaskstatsTypeAttrs::*;
        match self {
            Unspec => TASKSTATS_TYPE_UNSPEC,
            Pid(_) => TASKSTATS_TYPE_PID,
            Tgid(_) => TASKSTATS_TYPE_TGID,
            Stats(_) => TASKSTATS_TYPE_STATS,
            AggrPid(_, _) => TASKSTATS_TYPE_AGGR_PID,
            AggrTgid(_, _) => TASKSTATS_TYPE_AGGR_TGID,
            Null => TASKSTATS_TYPE_NULL,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use TaskstatsTypeAttrs::*;
        match self {
            Unspec => {},
            Pid(v) => NativeEndian::write_u32(buffer, *v),
            Tgid(v) => NativeEndian::write_u32(buffer, *v),
            Stats(s) => {
                let bytes: [u8; size_of::<Taskstats>()] = unsafe { std::mem::transmute(*s) };
                buffer.copy_from_slice(&bytes);
            },
            AggrPid(v, s) => {
                let nla_pid = TaskstatsTypeAttrs::Pid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);
                
                nla_pid.emit(buffer);
                nla_stats.emit(&mut buffer[nla_pid.buffer_len()..]);
            },
            AggrTgid(v, s) => {
                let nla_tgid = TaskstatsTypeAttrs::Tgid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);
                
                nla_tgid.emit(buffer);
                nla_stats.emit(&mut buffer[nla_tgid.buffer_len()..]);
            },
            Null => {},
        }
    }
}

fn parse_taskstats(payload: &[u8]) -> Result<Taskstats, DecodeError> {
    if payload.len() != size_of::<Taskstats>() {
        return Err(format!("invalid Taskstats length: {}", payload.len()).into())
    }

    let mut bytes = [0; size_of::<Taskstats>()];
    bytes.copy_from_slice(&payload[..size_of::<Taskstats>()]);
    Ok(unsafe { std::mem::transmute(bytes) })
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TaskstatsTypeAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_TYPE_UNSPEC => Self::Unspec,
            TASKSTATS_TYPE_PID => Self::Pid(
                parse_u32(payload)
                    .context("invalid TASKSTATS_TYPE_PID value")?,
            ),
            TASKSTATS_TYPE_TGID => Self::Tgid(
                parse_u32(payload)
                    .context("invalid TASKSTATS_TYPE_TGID value")?,
            ),
            TASKSTATS_TYPE_STATS => Self::Stats(
                parse_taskstats(payload)
                    .context("invalid TASKSTATS_TYPE_STATS value")?,
            ),
            TASKSTATS_TYPE_AGGR_PID => {
                let nlas = NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| TaskstatsTypeAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse TASKSTATS_TYPE_AGGR_PID attributes")?;
                if nlas.len() != 2 {
                    return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_PID attributes length: {}", nlas.len()
                    )))
                }
                let pid = match &nlas[0] {
                    TaskstatsTypeAttrs::Pid(pid) => *pid,
                    _ => return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_PID attributes[0] type"
                    )))
                };
                let stats = match &nlas[1] {
                    TaskstatsTypeAttrs::Stats(stats) => *stats,
                    _ => return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_PID attributes[1] type"
                    )))
                };
                Self::AggrPid(pid, stats)
            },
            TASKSTATS_TYPE_AGGR_TGID => {
                let nlas = NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| TaskstatsTypeAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse TASKSTATS_TYPE_AGGR_TGID attributes")?;
                if nlas.len() != 2 {
                    return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_TGID attributes length: {}", nlas.len()
                    )))
                }
                let tgid = match &nlas[0] {
                    TaskstatsTypeAttrs::Tgid(pid) => *pid,
                    _ => return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_TGID attributes[0] type"
                    )))
                };
                let stats = match &nlas[1] {
                    TaskstatsTypeAttrs::Stats(stats) => *stats,
                    _ => return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_TGID attributes[1] type"
                    )))
                };
                Self::AggrTgid(tgid, stats)
            },
            TASKSTATS_TYPE_NULL => Self::Null,
            kind => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {kind}"
                )))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn test_parse_taskstats_type_pid() {
        let type_pid_bytes = [
            8, 0, // nla_len
            1, 0, // nla_type
            1, 0, 0, 0 // pid
        ];

        let expected = TaskstatsTypeAttrs::Pid(1);
        let parsed_nla = TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&type_pid_bytes).unwrap()).unwrap();
        assert_eq!(parsed_nla, expected);
    }

    #[test]
    fn test_parse_taskstats_type_stats() {
        let type_stats_bytes = [
            0xa4, 1, // nla_len
            3, 0, // nla_type
            0xd, 0, // version
            0, 0, // hole: 2 bytes
            0, 0, 0, 0, // ac_exitcode
            2, // ac_flag
            0, // ac_nice
            0, 0, 0, 0, 0, 0, // hole: 6 bytes
            66, 8, 0, 0, 0, 0, 0, 0, // cpu_count
            0xbf, 0x5e, 0xe7, 6, 0, 0, 0, 0,  // cpu_delay_total
            0xfc, 1, 0, 0, 0, 0, 0, 0, // blkio_count
            0x8c, 51, 48, 13, 0, 0, 0, 0, // blkio_delay_total
            0, 0, 0, 0, 0, 0, 0, 0, // swapin_count
            0, 0, 0, 0, 0, 0, 0, 0, // swapin_delay_total
            0xd9, 8, 4, 33, 0, 0, 0, 0, // cpu_run_real_total
            0xc, 0xa1, 0x7a, 38, 0, 0, 0, 0, // cpu_run_virtual_total
            73, 79, 73, 74, 65, 0x6d, 64, 0, // as_common[0..8]
            0, 0, 0, 0, 0, 0, 0, 0, // as_common[8..16]
            0, 0, 0, 0, 0, 0, 0, 0, // as_common[16..24]
            0, 0, 0, 0, 0, 0, 0, 0, // as_common[24..32]
            0, // ac_sched
            0, 0, 0, // ac_pad
            0, 0, 0, 0, // __pad, hole: 4 bytes
            0, 0, 0, 0, // ac_uid
            0, 0, 0, 0, // ac_gid
            1, 0, 0, 0, // ac_pid
            0, 0, 0, 0, // ac_ppid
            0xe0, 0xf2, 0x9b, 65, // ac_btime
            0, 0, 0, 0, // hole: 4 bytes
            0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, // ac_etime
            44, 0x2c, 3, 0, 0, 0, 0, 0, // ac_utime
            0x1a, 0xe3, 9, 0, 0, 0, 0, 0, // ac_stime
            0x1b, 0x2a, 0, 0, 0, 0, 0, 0, // ac_minflt
            0xa2, 0, 0, 0, 0, 0, 0, 0, // ac_majflt
            11, 0xaa, 41, 0, 0, 0, 0, 0, // coremem
            0xc3, 0xff, 64, 1, 0, 0, 0, 0, // virtmem
            0xd4, 28, 0, 0, 0, 0, 0, 0, // hiwater_rss
            30, 0x8a, 3, 0, 0, 0, 0, 0, // hiwater_vm
            0, 0xa0, 0xa, 0, 0, 0, 0, 0, // read_char
            0, 74, 0, 0, 0, 0, 0, 0, // write_char
            0, 10, 0, 0, 0, 0, 0, 0, // read_syscalls
            0, 8, 0, 0, 0, 0, 0, 0, // write_syscalls
            0, 0xfc, 4, 1, 0, 0, 0, 0, // read_bytes
            0, 0, 0, 0, 0, 0, 0, 0, // write_bytes
            0, 0, 0, 0, 0, 0, 0, 0, // cancelled_write_bytes
            0xb9, 6, 0, 0, 0, 0, 0, 0, // nvcsw
            0xb0, 1, 0, 0, 0, 0, 0, 0, // nivcsw
            44, 0x2c, 3, 0, 0, 0, 0, 0, // ac_utimescaled
            0x1a, 0xe3, 9, 0, 0, 0, 0, 0,  // ac_stimescaled
            0xd9, 8, 4, 33, 0, 0, 0, 0, // cpu_scaled_run_real_total
            0, 0, 0, 0, 0, 0, 0, 0, // freepages_count
            0, 0, 0, 0, 0, 0, 0, 0, // freepages_delay_total
            0, 0, 0, 0, 0, 0, 0, 0, // thrashing_count
            0, 0, 0, 0, 0, 0, 0, 0, // thrashing_delay_total
            0xe0, 0xf2, 0x9b, 65, 0, 0, 0, 0, // ac_btime64
            0, 0, 0, 0, 0, 0, 0, 0, // compact_count
            0, 0, 0, 0, 0, 0, 0, 0, // compact_delay_total
            1, 0, 0, 0, // ac_tgid
            0, 0, 0, 0, // hole: 4 bytes
            0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, // ac_tgetime
            1, 3, 1, 0, 0, 0, 0, 0, // ac_exe_dev
            0x6b, 0xd, 0, 0, 0, 0, 0, 0, // ac_exe_inode
            0x1c, 18, 0, 0, 0, 0, 0, 0, // wpcopy_count
            13, 0xd8, 0xe4, 0, 0, 0, 0, 0  // wpcopy_delay_total
        ];


        let expected = TaskstatsTypeAttrs::Stats(Taskstats {
            version: 0xd,
            ac_exitcode: 0,
            ac_flag: 0x2,
            ac_nice: 0,
            cpu_count: 0x0842,
            cpu_delay_total: 0x6e75ebf,
            blkio_count: 0x1fc,
            blkio_delay_total: 0xd30338c,
            swapin_count: 0,
            swapin_delay_total: 0,
            cpu_run_real_total: 0x210408d9,
            cpu_run_virtual_total: 0x267aa10c,
            ac_comm: [
                73, 79, 73, 74, 65, 0x6d, 64, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            ac_sched: 0,
            ac_pad: [0, 0, 0],
            __pad: [0, 0, 0, 0],
            ac_uid: 0,
            ac_gid: 0,
            ac_pid: 1,
            ac_ppid: 0,
            ac_btime: 0x419bf2e0,
            ac_etime: 0x1fbbc7a2,
            ac_utime: 0x32c2c,
            ac_stime: 0x9e31a,
            ac_minflt: 0x2a1b,
            ac_majflt: 0xa2,
            coremem: 0x29aa0b,
            virtmem: 0x140ffc3,
            hiwater_rss: 0x1cd4,
            hiwater_vm: 0x38a1e,
            read_char: 0xaa000,
            write_char: 0x4a00,
            read_syscalls: 0xa00,
            write_syscalls: 0x800,
            read_bytes: 0x104fc00,
            write_bytes: 0,
            cancelled_write_bytes: 0,
            nvcsw: 0x6b9,
            nivcsw: 0x1b0,
            ac_utimescaled: 0x32c2c,
            ac_stimescaled: 0x9e31a,
            cpu_scaled_run_real_total: 0x210408d9,
            freepages_count: 0,
            freepages_delay_total: 0,
            thrashing_count: 0,
            thrashing_delay_total: 0,
            ac_btime64: 0x419bf2e0,
            compact_count: 0,
            compact_delay_total: 0,
            ac_tgid: 0x1,
            ac_tgetime: 0x1fbbc7a2,
            ac_exe_dev: 0x10301,
            ac_exe_inode: 0xd6b,
            wpcopy_count: 0x121c,
            wpcopy_delay_total: 0xe4d80d,
        });
        let parsed_nla = TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&type_stats_bytes).unwrap()).unwrap();

        assert_eq!(parsed_nla, expected);
    }

    #[test]
    fn test_parse_taskstats_type_agg_pid_stats() {
        let type_pid_stats_bytes = [
            0xb0, 1, // nla_len
            4, 0, // nla_type
            // first nested nla
            8, 0, // nla_len
            1, 0, // nla_type
            1, 0, 0, 0, // pid
            // second nested nla
            0xa4, 1, // nla_len
            3, 0, // nla_type
            0xd, 0, // version
            0, 0, // hole: 2 bytes
            0, 0, 0, 0, // ac_exitcode
            2, // ac_flag
            0, // ac_nice
            0, 0, 0, 0, 0, 0, // hole: 6 bytes
            66, 8, 0, 0, 0, 0, 0, 0, // cpu_count
            0xbf, 0x5e, 0xe7, 6, 0, 0, 0, 0, // cpu_delay_total
            0xfc, 1, 0, 0, 0, 0, 0, 0, // blkio_count
            0x8c, 51, 48, 13, 0, 0, 0, 0, // blkio_delay_total
            0, 0, 0, 0, 0, 0, 0, 0, // swapin_count
            0, 0, 0, 0, 0, 0, 0, 0, // swapin_delay_total
            0xd9, 8, 4, 33, 0, 0, 0, 0, // cpu_run_real_total
            0xc, 0xa1, 0x7a, 38, 0, 0, 0, 0, // cpu_run_virtual_total
            73, 79, 73, 74, 65, 0x6d, 64, 0, // as_common[0..8]
            0, 0, 0, 0, 0, 0, 0, 0, // as_common[8..16]
            0, 0, 0, 0, 0, 0, 0, 0, // as_common[16..24]
            0, 0, 0, 0, 0, 0, 0, 0, // as_common[24..32]
            0, // ac_sched
            0, 0, 0, // ac_pad
            0, 0, 0, 0, // __pad, hole: 4 bytes
            0, 0, 0, 0, // ac_uid
            0, 0, 0, 0, // ac_gid
            1, 0, 0, 0, // ac_pid
            0, 0, 0, 0, // ac_ppid
            0xe0, 0xf2, 0x9b, 65, // ac_btime
            0, 0, 0, 0, // hole: 4 bytes
            0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, // ac_etime
            44, 0x2c, 3, 0, 0, 0, 0, 0, // ac_utime
            0x1a, 0xe3, 9, 0, 0, 0, 0, 0, // ac_stime
            0x1b, 0x2a, 0, 0, 0, 0, 0, 0, // ac_minflt
            0xa2, 0, 0, 0, 0, 0, 0, 0, // ac_majflt
            11, 0xaa, 41, 0, 0, 0, 0, 0, // coremem
            0xc3, 0xff, 64, 1, 0, 0, 0, 0, // virtmem
            0xd4, 28, 0, 0, 0, 0, 0, 0, // hiwater_rss
            30, 0x8a, 3, 0, 0, 0, 0, 0, // hiwater_vm
            0, 0xa0, 0xa, 0, 0, 0, 0, 0, // read_char
            0, 74, 0, 0, 0, 0, 0, 0, // write_char
            0, 10, 0, 0, 0, 0, 0, 0, // read_syscalls
            0, 8, 0, 0, 0, 0, 0, 0, // write_syscalls
            0, 0xfc, 4, 1, 0, 0, 0, 0, // read_bytes
            0, 0, 0, 0, 0, 0, 0, 0, // write_bytes
            0, 0, 0, 0, 0, 0, 0, 0, // cancelled_write_bytes
            0xb9, 6, 0, 0, 0, 0, 0, 0, // nvcsw
            0xb0, 1, 0, 0, 0, 0, 0, 0, // nivcsw
            44, 0x2c, 3, 0, 0, 0, 0, 0, // ac_utimescaled
            0x1a, 0xe3, 9, 0, 0, 0, 0, 0, // ac_stimescaled
            0xd9, 8, 4, 33, 0, 0, 0, 0, // cpu_scaled_run_real_total
            0, 0, 0, 0, 0, 0, 0, 0, // freepages_count
            0, 0, 0, 0, 0, 0, 0, 0, // freepages_delay_total
            0, 0, 0, 0, 0, 0, 0, 0, // thrashing_count
            0, 0, 0, 0, 0, 0, 0, 0, // thrashing_delay_total
            0xe0, 0xf2, 0x9b, 65, 0, 0, 0, 0, // ac_btime64
            0, 0, 0, 0, 0, 0, 0, 0, // compact_count
            0, 0, 0, 0, 0, 0, 0, 0, // compact_delay_total
            1, 0, 0, 0, // ac_tgid
            0, 0, 0, 0, // hole: 4 bytes
            0xa2, 0xc7, 0xbb, 0x1f, 0, 0, 0, 0, // ac_tgetime
            1, 3, 1, 0, 0, 0, 0, 0, // ac_exe_dev
            0x6b, 0xd, 0, 0, 0, 0, 0, 0, // ac_exe_inode
            0x1c, 18, 0, 0, 0, 0, 0, 0, // wpcopy_count
            13, 0xd8, 0xe4, 0, 0, 0, 0, 0 // wpcopy_delay_total
        ];

        let expected_pid = 1;
        let expected_stats = Taskstats {
            version: 0xd,
            ac_exitcode: 0,
            ac_flag: 0x2,
            ac_nice: 0,
            cpu_count: 0x0842,
            cpu_delay_total: 0x6e75ebf,
            blkio_count: 0x1fc,
            blkio_delay_total: 0xd30338c,
            swapin_count: 0,
            swapin_delay_total: 0,
            cpu_run_real_total: 0x210408d9,
            cpu_run_virtual_total: 0x267aa10c,
            ac_comm: [
                73, 79, 73, 74, 65, 0x6d, 64, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            ac_sched: 0,
            ac_pad: [0, 0, 0],
            __pad: [0, 0, 0, 0],
            ac_uid: 0,
            ac_gid: 0,
            ac_pid: 1,
            ac_ppid: 0,
            ac_btime: 0x419bf2e0,
            ac_etime: 0x1fbbc7a2,
            ac_utime: 0x32c2c,
            ac_stime: 0x9e31a,
            ac_minflt: 0x2a1b,
            ac_majflt: 0xa2,
            coremem: 0x29aa0b,
            virtmem: 0x140ffc3,
            hiwater_rss: 0x1cd4,
            hiwater_vm: 0x38a1e,
            read_char: 0xaa000,
            write_char: 0x4a00,
            read_syscalls: 0xa00,
            write_syscalls: 0x800,
            read_bytes: 0x104fc00,
            write_bytes: 0,
            cancelled_write_bytes: 0,
            nvcsw: 0x6b9,
            nivcsw: 0x1b0,
            ac_utimescaled: 0x32c2c,
            ac_stimescaled: 0x9e31a,
            cpu_scaled_run_real_total: 0x210408d9,
            freepages_count: 0,
            freepages_delay_total: 0,
            thrashing_count: 0,
            thrashing_delay_total: 0,
            ac_btime64: 0x419bf2e0,
            compact_count: 0,
            compact_delay_total: 0,
            ac_tgid: 0x1,
            ac_tgetime: 0x1fbbc7a2,
            ac_exe_dev: 0x10301,
            ac_exe_inode: 0xd6b,
            wpcopy_count: 0x121c,
            wpcopy_delay_total: 0xe4d80d,
        };
        let expected = TaskstatsTypeAttrs::AggrPid(expected_pid, expected_stats);

        let parsed_nla = TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&type_pid_stats_bytes).unwrap()).unwrap();

        assert_eq!(parsed_nla, expected);

    }

    #[test]
    fn test_emit_parse_taskstats_type_pid() {
        let nla = TaskstatsTypeAttrs::Pid(123);
        let mut buffer = vec![0; nla.buffer_len()];
        nla.emit(&mut buffer);
        assert_eq!(nla.buffer_len(), 8);

        let parsed_nla: TaskstatsTypeAttrs = TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
        assert_eq!(parsed_nla, nla);
    }


    #[test]
    fn test_emit_parse_taskstats_type_stats() {
        let nla = TaskstatsTypeAttrs::Stats(Taskstats {
            version: 0xd,
            ac_exitcode: 0,
            ac_flag: 0x2,
            ac_nice: 0,
            cpu_count: 0x0842,
            cpu_delay_total: 0x6e75ebf,
            blkio_count: 0x1fc,
            blkio_delay_total: 0xd30338c,
            swapin_count: 0,
            swapin_delay_total: 0,
            cpu_run_real_total: 0x210408d9,
            cpu_run_virtual_total: 0x267aa10c,
            ac_comm: [
                73, 79, 73, 74, 65, 0x6d, 64, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            ac_sched: 0,
            ac_pad: [0, 0, 0],
            __pad: [0, 0, 0, 0],
            ac_uid: 0,
            ac_gid: 0,
            ac_pid: 1,
            ac_ppid: 0,
            ac_btime: 0x419bf2e0,
            ac_etime: 0x1fbbc7a2,
            ac_utime: 0x32c2c,
            ac_stime: 0x9e31a,
            ac_minflt: 0x2a1b,
            ac_majflt: 0xa2,
            coremem: 0x29aa0b,
            virtmem: 0x140ffc3,
            hiwater_rss: 0x1cd4,
            hiwater_vm: 0x38a1e,
            read_char: 0xaa000,
            write_char: 0x4a00,
            read_syscalls: 0xa00,
            write_syscalls: 0x800,
            read_bytes: 0x104fc00,
            write_bytes: 0,
            cancelled_write_bytes: 0,
            nvcsw: 0x6b9,
            nivcsw: 0x1b0,
            ac_utimescaled: 0x32c2c,
            ac_stimescaled: 0x9e31a,
            cpu_scaled_run_real_total: 0x210408d9,
            freepages_count: 0,
            freepages_delay_total: 0,
            thrashing_count: 0,
            thrashing_delay_total: 0,
            ac_btime64: 0x419bf2e0,
            compact_count: 0,
            compact_delay_total: 0,
            ac_tgid: 0x1,
            ac_tgetime: 0x1fbbc7a2,
            ac_exe_dev: 0x10301,
            ac_exe_inode: 0xd6b,
            wpcopy_count: 0x121c,
            wpcopy_delay_total: 0xe4d80d,
        });
        let mut buffer = vec![0; nla.buffer_len()];
        nla.emit(&mut buffer);
        assert_eq!(nla.buffer_len(), 420);

        let parsed_nla = TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
        assert_eq!(parsed_nla, nla);
    }

    #[test]
    fn test_emit_parse_taskstats_type_agg_pid_stats() {
        let nla = TaskstatsTypeAttrs::AggrPid(123, Taskstats {
            version: 0xd,
            ac_exitcode: 0,
            ac_flag: 0x2,
            ac_nice: 0,
            cpu_count: 0x0842,
            cpu_delay_total: 0x6e75ebf,
            blkio_count: 0x1fc,
            blkio_delay_total: 0xd30338c,
            swapin_count: 0,
            swapin_delay_total: 0,
            cpu_run_real_total: 0x210408d9,
            cpu_run_virtual_total: 0x267aa10c,
            ac_comm: [
                73, 79, 73, 74, 65, 0x6d, 64, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            ac_sched: 0,
            ac_pad: [0, 0, 0],
            __pad: [0, 0, 0, 0],
            ac_uid: 0,
            ac_gid: 0,
            ac_pid: 1,
            ac_ppid: 0,
            ac_btime: 0x419bf2e0,
            ac_etime: 0x1fbbc7a2,
            ac_utime: 0x32c2c,
            ac_stime: 0x9e31a,
            ac_minflt: 0x2a1b,
            ac_majflt: 0xa2,
            coremem: 0x29aa0b,
            virtmem: 0x140ffc3,
            hiwater_rss: 0x1cd4,
            hiwater_vm: 0x38a1e,
            read_char: 0xaa000,
            write_char: 0x4a00,
            read_syscalls: 0xa00,
            write_syscalls: 0x800,
            read_bytes: 0x104fc00,
            write_bytes: 0,
            cancelled_write_bytes: 0,
            nvcsw: 0x6b9,
            nivcsw: 0x1b0,
            ac_utimescaled: 0x32c2c,
            ac_stimescaled: 0x9e31a,
            cpu_scaled_run_real_total: 0x210408d9,
            freepages_count: 0,
            freepages_delay_total: 0,
            thrashing_count: 0,
            thrashing_delay_total: 0,
            ac_btime64: 0x419bf2e0,
            compact_count: 0,
            compact_delay_total: 0,
            ac_tgid: 0x1,
            ac_tgetime: 0x1fbbc7a2,
            ac_exe_dev: 0x10301,
            ac_exe_inode: 0xd6b,
            wpcopy_count: 0x121c,
            wpcopy_delay_total: 0xe4d80d,
        });
        let mut buffer = vec![0; nla.buffer_len()];
        nla.emit(&mut buffer);
        assert_eq!(nla.buffer_len(), 432);

        let parsed_nla = TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
        assert_eq!(parsed_nla, nla);
    }
}