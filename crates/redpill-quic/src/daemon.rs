//! Client daemon mode: backgrounding, PID file, stop/status.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::info;

/// Platform-specific PID file location.
pub fn pid_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        // macOS: ~/Library/Application Support/redpill/redpill.pid
        if let Some(home) = std::env::var_os("HOME") {
            let dir = PathBuf::from(home).join("Library/Application Support/redpill");
            let _ = fs::create_dir_all(&dir);
            return dir.join("redpill.pid");
        }
    }
    PathBuf::from("/var/run/redpill.pid")
}

/// Platform-specific log file location.
pub fn log_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        if let Some(home) = std::env::var_os("HOME") {
            let dir = PathBuf::from(home).join("Library/Logs");
            let _ = fs::create_dir_all(&dir);
            return dir.join("redpill.log");
        }
    }
    let dir = PathBuf::from("/var/log/redpill");
    let _ = fs::create_dir_all(&dir);
    dir.join("client.log")
}

/// Platform-specific IPC socket path.
pub fn socket_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        if let Some(home) = std::env::var_os("HOME") {
            let dir = PathBuf::from(home).join("Library/Application Support/redpill");
            let _ = fs::create_dir_all(&dir);
            return dir.join("redpill.sock");
        }
    }
    PathBuf::from("/var/run/redpill.sock")
}

/// Write PID file. Returns the path for logging.
pub fn write_pid(path: &Path) -> anyhow::Result<()> {
    let pid = std::process::id();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, pid.to_string())?;
    info!("PID file written: {} (pid={})", path.display(), pid);
    Ok(())
}

/// Read PID from file. Returns None if file doesn't exist or is invalid.
pub fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Remove PID file.
pub fn remove_pid(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Check if a daemon is already running (by PID file + process check).
pub fn is_running() -> Option<u32> {
    let path = pid_path();
    let pid = read_pid(&path)?;

    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            return Some(pid);
        }
        remove_pid(&path);
        None
    }

    #[cfg(not(unix))]
    {
        Some(pid)
    }
}

/// Stop a running daemon by sending SIGTERM.
pub fn stop_daemon() -> anyhow::Result<()> {
    let path = pid_path();
    let pid =
        read_pid(&path).ok_or_else(|| anyhow::anyhow!("No daemon running (PID file not found)"))?;

    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        if ret == 0 {
            println!("Sent SIGTERM to daemon (pid={pid})");
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let check = unsafe { libc::kill(pid as i32, 0) };
                if check != 0 {
                    remove_pid(&path);
                    println!("Daemon stopped.");
                    return Ok(());
                }
            }
            println!("Daemon still running after 2s - check manually.");
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                remove_pid(&path);
                anyhow::bail!("Daemon not running (stale PID file removed)");
            }
            anyhow::bail!("Failed to send SIGTERM: {err}");
        }
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        anyhow::bail!("Daemon stop not supported on this platform");
    }
}

/// Daemonize the current process (Unix fork/setsid).
/// Returns Ok(()) in the child, Err in the parent (which should exit).
#[cfg(unix)]
pub fn daemonize(log_path: &Path) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;

    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork() failed: {}", std::io::Error::last_os_error()),
        0 => {}                     // child continues
        _ => std::process::exit(0), // parent exits
    }

    if unsafe { libc::setsid() } == -1 {
        anyhow::bail!("setsid() failed: {}", std::io::Error::last_os_error());
    }

    // Second fork (prevent acquiring a controlling terminal)
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork() failed: {}", std::io::Error::last_os_error()),
        0 => {}                     // grandchild continues
        _ => std::process::exit(0), // child exits
    }

    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let log_fd = log_file.as_raw_fd();

    unsafe {
        libc::dup2(log_fd, libc::STDOUT_FILENO);
        libc::dup2(log_fd, libc::STDERR_FILENO);
        // Redirect stdin to /dev/null
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::close(devnull);
        }
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn daemonize(_log_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("Daemon mode not supported on this platform")
}
