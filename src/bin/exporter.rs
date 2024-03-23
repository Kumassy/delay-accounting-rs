
use anyhow::{anyhow, bail, Context, Result};
use std::net::SocketAddr;
use prometheus_exporter::prometheus::{self, labels, register_gauge_vec};

fn main() -> Result<()> {
    pretty_env_logger::init();

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
        }
    }

    Ok(())
}