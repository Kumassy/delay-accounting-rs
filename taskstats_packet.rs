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
    RegisterCpumask(String),
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