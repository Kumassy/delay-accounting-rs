use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::parse_u32,
    traits::*,
    DecodeError,
};
use std::mem::size_of_val;

/// Command code definition of Taskstats family
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskstatsCmd {
    Unspec = 0, /* Reserved */
    Get,        /* user->kernel request/get-response */
    New,        /* kernel->user event */
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
            cmd => return Err(DecodeError::from(format!("Unknown control command: {cmd}"))),
        })
    }
}

/// Payload of taskstats controller
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskstatsCtrl<T> {
    /// Command code of this message
    pub cmd: TaskstatsCmd,
    /// Netlink attributes in this message
    pub nlas: Vec<T>,
}

impl<T> GenlFamily for TaskstatsCtrl<T> {
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

impl<T: Nla> Emitable for TaskstatsCtrl<T> {
    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for TaskstatsCtrl<TaskstatsCmdAttrs> {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            nlas: parse_cmd_attrs(buf)?,
        })
    }
}

impl ParseableParametrized<[u8], GenlHeader> for TaskstatsCtrl<TaskstatsTypeAttrs> {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            nlas: parse_type_attrs(buf)?,
        })
    }
}

fn parse_cmd_attrs(buf: &[u8]) -> Result<Vec<TaskstatsCmdAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| TaskstatsCmdAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse control message attributes")?;
    Ok(nlas)
}

fn parse_type_attrs(buf: &[u8]) -> Result<Vec<TaskstatsTypeAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| TaskstatsTypeAttrs::parse(&nla)))
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
            Unspec => {}
            Pid(v) => NativeEndian::write_u32(buffer, *v),
            Tgid(v) => NativeEndian::write_u32(buffer, *v),
            RegisterCpumask(v) => {
                buffer[..v.len()].copy_from_slice(v);
            }
            DeregisterCpumask(v) => {
                buffer[..v.len()].copy_from_slice(v);
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TaskstatsCmdAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_CMD_ATTR_UNSPEC => Self::Unspec,
            TASKSTATS_CMD_ATTR_PID => {
                Self::Pid(parse_u32(payload).context("invalid TASKSTATS_CMD_ATTR_PID value")?)
            }
            TASKSTATS_CMD_ATTR_TGID => {
                Self::Tgid(parse_u32(payload).context("invalid TASKSTATS_CMD_ATTR_TGID value")?)
            }
            TASKSTATS_CMD_ATTR_REGISTER_CPUMASK => {
                let bytes = payload.to_vec();
                Self::RegisterCpumask(bytes)
            }
            TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK => {
                let bytes = payload.to_vec();
                Self::DeregisterCpumask(bytes)
            }
            kind => return Err(DecodeError::from(format!("Unknown NLA type: {kind}"))),
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

    // // v9
    pub thrashing_count: u64,
    pub thrashing_delay_total: u64,

    // // v10
    pub ac_btime64: u64,

    // // v11
    pub compact_count: u64,
    pub compact_delay_total: u64,

    // // v12
    pub ac_tgid: u32,
    pub ac_tgetime: u64,
    pub ac_exe_dev: u64,
    pub ac_exe_inode: u64,

    // // v13
    pub wpcopy_count: u64,
    pub wpcopy_delay_total: u64,

    // v14
    // pub irq_count: u64,
    // pub irq_delay_total: u64,
}

fn size_of_taskstats(version: u16) -> usize {
    match version {
        7 | 8 => 328,
        9 => 344,
        10 => 352,
        11 => 368,
        12 => 400,
        13 => 416,
        14 => 432,
        _ => 0,
    }
}

pub const TAKSTATS_SUPPORTED_VERSION_MIN: u16 = 7;
pub const TAKSTATS_SUPPORTED_VERSION_MAX: u16 = 14;

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
            Stats(s) => size_of_taskstats(s.version),
            AggrPid(v, s) => {
                let nla_pid = TaskstatsTypeAttrs::Pid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);

                nla_pid.buffer_len() + nla_stats.buffer_len()
            }
            AggrTgid(v, s) => {
                let nla_tgid = TaskstatsTypeAttrs::Tgid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);

                nla_tgid.buffer_len() + nla_stats.buffer_len()
            }
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
            Unspec => {}
            Pid(v) => NativeEndian::write_u32(buffer, *v),
            Tgid(v) => NativeEndian::write_u32(buffer, *v),
            Stats(s) => {
                if s.version < TAKSTATS_SUPPORTED_VERSION_MIN
                    || s.version > TAKSTATS_SUPPORTED_VERSION_MAX
                {
                    return;
                }

                NativeEndian::write_u16(&mut buffer[0..2], s.version);
                NativeEndian::write_u32(&mut buffer[4..8], s.ac_exitcode);
                buffer[8] = s.ac_flag;
                buffer[9] = s.ac_nice;
                // hole: 6 bytes
                NativeEndian::write_u64(&mut buffer[16..24], s.cpu_count);
                NativeEndian::write_u64(&mut buffer[24..32], s.cpu_delay_total);
                NativeEndian::write_u64(&mut buffer[32..40], s.blkio_count);
                NativeEndian::write_u64(&mut buffer[40..48], s.blkio_delay_total);
                NativeEndian::write_u64(&mut buffer[48..56], s.swapin_count);
                NativeEndian::write_u64(&mut buffer[56..64], s.swapin_delay_total);
                NativeEndian::write_u64(&mut buffer[64..72], s.cpu_run_real_total);
                NativeEndian::write_u64(&mut buffer[72..80], s.cpu_run_virtual_total);
                buffer[80..112].copy_from_slice(&s.ac_comm);
                buffer[112] = s.ac_sched;
                buffer[113..116].copy_from_slice(&s.ac_pad);
                buffer[116..120].copy_from_slice(&s.__pad);  // __pad, hole: 4 bytes
                NativeEndian::write_u32(&mut buffer[120..124], s.ac_uid);
                NativeEndian::write_u32(&mut buffer[124..128], s.ac_gid);
                NativeEndian::write_u32(&mut buffer[128..132], s.ac_pid);
                NativeEndian::write_u32(&mut buffer[132..136], s.ac_ppid);
                NativeEndian::write_u32(&mut buffer[136..140], s.ac_btime);
                // hole: 4 bytes
                NativeEndian::write_u64(&mut buffer[144..152], s.ac_etime);
                NativeEndian::write_u64(&mut buffer[152..160], s.ac_utime);
                NativeEndian::write_u64(&mut buffer[160..168], s.ac_stime);
                NativeEndian::write_u64(&mut buffer[168..176], s.ac_minflt);
                NativeEndian::write_u64(&mut buffer[176..184], s.ac_majflt);
                NativeEndian::write_u64(&mut buffer[184..192], s.coremem);
                NativeEndian::write_u64(&mut buffer[192..200], s.virtmem);
                NativeEndian::write_u64(&mut buffer[200..208], s.hiwater_rss);
                NativeEndian::write_u64(&mut buffer[208..216], s.hiwater_vm);
                NativeEndian::write_u64(&mut buffer[216..224], s.read_char);
                NativeEndian::write_u64(&mut buffer[224..232], s.write_char);
                NativeEndian::write_u64(&mut buffer[232..240], s.read_syscalls);
                NativeEndian::write_u64(&mut buffer[240..248], s.write_syscalls);
                NativeEndian::write_u64(&mut buffer[248..256], s.read_bytes);
                NativeEndian::write_u64(&mut buffer[256..264], s.write_bytes);
                NativeEndian::write_u64(&mut buffer[264..272], s.cancelled_write_bytes);
                NativeEndian::write_u64(&mut buffer[272..280], s.nvcsw);
                NativeEndian::write_u64(&mut buffer[280..288], s.nivcsw);
                NativeEndian::write_u64(&mut buffer[288..296], s.ac_utimescaled);
                NativeEndian::write_u64(&mut buffer[296..304], s.ac_stimescaled);
                NativeEndian::write_u64(&mut buffer[304..312], s.cpu_scaled_run_real_total);
                NativeEndian::write_u64(&mut buffer[312..320], s.freepages_count);
                NativeEndian::write_u64(&mut buffer[320..328], s.freepages_delay_total);

                if s.version >= 9 {
                    NativeEndian::write_u64(&mut buffer[328..336], s.thrashing_count);
                    NativeEndian::write_u64(&mut buffer[336..344], s.thrashing_delay_total);

                }
                if s.version >= 10 {
                    NativeEndian::write_u64(&mut buffer[344..352], s.ac_btime64);
                }
                if s.version >= 11 {
                    NativeEndian::write_u64(&mut buffer[352..360], s.compact_count);
                    NativeEndian::write_u64(&mut buffer[360..368], s.compact_delay_total);
                }
                if s.version >= 12 {
                    NativeEndian::write_u32(&mut buffer[368..372], s.ac_tgid);
                    // hole: 4 bytes
                    NativeEndian::write_u64(&mut buffer[376..384], s.ac_tgetime);
                    NativeEndian::write_u64(&mut buffer[384..392], s.ac_exe_dev);
                    NativeEndian::write_u64(&mut buffer[392..400], s.ac_exe_inode);
                }
                if s.version >= 13 {
                    NativeEndian::write_u64(&mut buffer[400..408], s.wpcopy_count);
                    NativeEndian::write_u64(&mut buffer[408..416], s.wpcopy_delay_total);
                }
            }
            AggrPid(v, s) => {
                let nla_pid = TaskstatsTypeAttrs::Pid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);

                nla_pid.emit(buffer);
                nla_stats.emit(&mut buffer[nla_pid.buffer_len()..]);
            }
            AggrTgid(v, s) => {
                let nla_tgid = TaskstatsTypeAttrs::Tgid(*v);
                let nla_stats = TaskstatsTypeAttrs::Stats(*s);

                nla_tgid.emit(buffer);
                nla_stats.emit(&mut buffer[nla_tgid.buffer_len()..]);
            }
            Null => {}
        }
    }
}

fn parse_taskstats(payload: &[u8]) -> Result<Taskstats, DecodeError> {
    let version = NativeEndian::read_u16(&payload[0..2]);
    if payload.len() != size_of_taskstats(version) {
        return Err(format!("invalid Taskstats length: {}", payload.len()).into());
    }

    let mut taskstat = Taskstats {
        version,
        ac_exitcode: NativeEndian::read_u32(&payload[4..8]),
        ac_flag: payload[8],
        ac_nice: payload[9],
        // hole: 6 bytes
        cpu_count: NativeEndian::read_u64(&payload[16..24]),
        cpu_delay_total: NativeEndian::read_u64(&payload[24..32]),
        blkio_count: NativeEndian::read_u64(&payload[32..40]),
        blkio_delay_total: NativeEndian::read_u64(&payload[40..48]),
        swapin_count: NativeEndian::read_u64(&payload[48..56]),
        swapin_delay_total: NativeEndian::read_u64(&payload[56..64]),
        cpu_run_real_total: NativeEndian::read_u64(&payload[64..72]),
        cpu_run_virtual_total: NativeEndian::read_u64(&payload[72..80]),
        ac_comm: payload[80..112].try_into().map_err(|e| format!("invalid ac_comm: {}", e))?,
        ac_sched: payload[112],
        ac_pad: payload[113..116].try_into().map_err(|e| format!("invalid ac_pad: {}", e))?,
        __pad: payload[116..120].try_into().map_err(|e| format!("invalid __pad: {}", e))?, // __pad, hole: 4 bytes
        ac_uid: NativeEndian::read_u32(&payload[120..124]),
        ac_gid: NativeEndian::read_u32(&payload[124..128]),
        ac_pid: NativeEndian::read_u32(&payload[128..132]),
        ac_ppid: NativeEndian::read_u32(&payload[132..136]),
        ac_btime: NativeEndian::read_u32(&payload[136..140]),
        // hole: 4 bytes
        ac_etime: NativeEndian::read_u64(&payload[144..152]),
        ac_utime: NativeEndian::read_u64(&payload[152..160]),
        ac_stime: NativeEndian::read_u64(&payload[160..168]),
        ac_minflt: NativeEndian::read_u64(&payload[168..176]),
        ac_majflt: NativeEndian::read_u64(&payload[176..184]),
        coremem: NativeEndian::read_u64(&payload[184..192]),
        virtmem: NativeEndian::read_u64(&payload[192..200]),
        hiwater_rss: NativeEndian::read_u64(&payload[200..208]),
        hiwater_vm: NativeEndian::read_u64(&payload[208..216]),
        read_char: NativeEndian::read_u64(&payload[216..224]),
        write_char: NativeEndian::read_u64(&payload[224..232]),
        read_syscalls: NativeEndian::read_u64(&payload[232..240]),
        write_syscalls: NativeEndian::read_u64(&payload[240..248]),
        read_bytes: NativeEndian::read_u64(&payload[248..256]),
        write_bytes: NativeEndian::read_u64(&payload[256..264]),
        cancelled_write_bytes: NativeEndian::read_u64(&payload[264..272]),
        nvcsw: NativeEndian::read_u64(&payload[272..280]),
        nivcsw: NativeEndian::read_u64(&payload[280..288]),
        ac_utimescaled: NativeEndian::read_u64(&payload[288..296]),
        ac_stimescaled: NativeEndian::read_u64(&payload[296..304]),
        cpu_scaled_run_real_total: NativeEndian::read_u64(&payload[304..312]),
        freepages_count: NativeEndian::read_u64(&payload[312..320]),
        freepages_delay_total: NativeEndian::read_u64(&payload[320..328]),

        ..Default::default()
    };

    if version >= 9 {
        taskstat.thrashing_count = NativeEndian::read_u64(&payload[328..336]);
        taskstat.thrashing_delay_total = NativeEndian::read_u64(&payload[336..344]);
    }
    if version >= 10 {
        taskstat.ac_btime64 = NativeEndian::read_u64(&payload[344..352]);
    }
    if version >= 11 {
        taskstat.compact_count = NativeEndian::read_u64(&payload[352..360]);
        taskstat.compact_delay_total = NativeEndian::read_u64(&payload[360..368]);
    }
    if version >= 12 {
        taskstat.ac_tgid = NativeEndian::read_u32(&payload[368..372]);
        // hole: 4 bytes
        taskstat.ac_tgetime = NativeEndian::read_u64(&payload[376..384]);
        taskstat.ac_exe_dev = NativeEndian::read_u64(&payload[384..392]);
        taskstat.ac_exe_inode = NativeEndian::read_u64(&payload[392..400]);
    }
    if version >= 13 {
        taskstat.wpcopy_count = NativeEndian::read_u64(&payload[400..408]);
        taskstat.wpcopy_delay_total = NativeEndian::read_u64(&payload[408..416]);
    }

    Ok(taskstat)
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TaskstatsTypeAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_TYPE_UNSPEC => Self::Unspec,
            TASKSTATS_TYPE_PID => {
                Self::Pid(parse_u32(payload).context("invalid TASKSTATS_TYPE_PID value")?)
            }
            TASKSTATS_TYPE_TGID => {
                Self::Tgid(parse_u32(payload).context("invalid TASKSTATS_TYPE_TGID value")?)
            }
            TASKSTATS_TYPE_STATS => {
                Self::Stats(parse_taskstats(payload).context("invalid TASKSTATS_TYPE_STATS value")?)
            }
            TASKSTATS_TYPE_AGGR_PID => {
                let nlas = NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| TaskstatsTypeAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse TASKSTATS_TYPE_AGGR_PID attributes")?;
                if nlas.len() != 2 {
                    return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_PID attributes length: {}",
                        nlas.len()
                    )));
                }
                let pid = match &nlas[0] {
                    TaskstatsTypeAttrs::Pid(pid) => *pid,
                    _ => {
                        return Err(DecodeError::from(
                            "Invalid TASKSTATS_TYPE_AGGR_PID attributes[0] type",
                        ))
                    }
                };
                let stats = match &nlas[1] {
                    TaskstatsTypeAttrs::Stats(stats) => *stats,
                    _ => {
                        return Err(DecodeError::from(
                            "Invalid TASKSTATS_TYPE_AGGR_PID attributes[1] type",
                        ))
                    }
                };
                Self::AggrPid(pid, stats)
            }
            TASKSTATS_TYPE_AGGR_TGID => {
                let nlas = NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| TaskstatsTypeAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse TASKSTATS_TYPE_AGGR_TGID attributes")?;
                if nlas.len() != 2 {
                    return Err(DecodeError::from(format!(
                        "Invalid TASKSTATS_TYPE_AGGR_TGID attributes length: {}",
                        nlas.len()
                    )));
                }
                let tgid = match &nlas[0] {
                    TaskstatsTypeAttrs::Tgid(pid) => *pid,
                    _ => {
                        return Err(DecodeError::from(
                            "Invalid TASKSTATS_TYPE_AGGR_TGID attributes[0] type",
                        ))
                    }
                };
                let stats = match &nlas[1] {
                    TaskstatsTypeAttrs::Stats(stats) => *stats,
                    _ => {
                        return Err(DecodeError::from(
                            "Invalid TASKSTATS_TYPE_AGGR_TGID attributes[1] type",
                        ))
                    }
                };
                Self::AggrTgid(tgid, stats)
            }
            TASKSTATS_TYPE_NULL => Self::Null,
            kind => return Err(DecodeError::from(format!("Unknown NLA type: {kind}"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_taskstats_type_pid() {
        let type_pid_bytes = [
            8, 0, // nla_len
            1, 0, // nla_type
            1, 0, 0, 0, // pid
        ];

        let expected = TaskstatsTypeAttrs::Pid(1);
        let parsed_nla =
            TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&type_pid_bytes).unwrap()).unwrap();
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
            13, 0xd8, 0xe4, 0, 0, 0, 0, 0, // wpcopy_delay_total
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
                73, 79, 73, 74, 65, 0x6d, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
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
        let parsed_nla =
            TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&type_stats_bytes).unwrap()).unwrap();

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
            13, 0xd8, 0xe4, 0, 0, 0, 0, 0, // wpcopy_delay_total
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
                73, 79, 73, 74, 65, 0x6d, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
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

        let parsed_nla =
            TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&type_pid_stats_bytes).unwrap())
                .unwrap();

        assert_eq!(parsed_nla, expected);
    }

    #[test]
    fn test_emit_parse_taskstats_type_pid() {
        let nla = TaskstatsTypeAttrs::Pid(123);
        let mut buffer = vec![0; nla.buffer_len()];
        nla.emit(&mut buffer);
        assert_eq!(nla.buffer_len(), 8);

        let parsed_nla: TaskstatsTypeAttrs =
            TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
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
                73, 79, 73, 74, 65, 0x6d, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
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

        let parsed_nla =
            TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
        assert_eq!(parsed_nla, nla);
    }

    #[test]
    fn test_emit_parse_taskstats_type_agg_pid_stats() {
        let nla = TaskstatsTypeAttrs::AggrPid(
            123,
            Taskstats {
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
                    73, 79, 73, 74, 65, 0x6d, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            },
        );
        let mut buffer = vec![0; nla.buffer_len()];
        nla.emit(&mut buffer);
        assert_eq!(nla.buffer_len(), 432);

        let parsed_nla =
            TaskstatsTypeAttrs::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
        assert_eq!(parsed_nla, nla);
    }
}
