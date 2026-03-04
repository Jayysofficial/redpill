use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("TUN device is only supported on Linux and macOS")]
    UnsupportedPlatform,
}

/// TUN device name (e.g. "redpill0").
#[cfg(target_os = "linux")]
const IFF_TUN: libc::c_short = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: libc::c_short = 0x1000;

/// A TUN device handle.
#[cfg(unix)]
pub struct TunDevice {
    fd: RawFd,
    name: String,
}

/// A TUN device handle (Windows - wintun ring buffer).
#[cfg(target_os = "windows")]
pub struct TunDevice {
    session: std::sync::Arc<wintun::Session>,
    name: String,
}

impl TunDevice {
    /// Create and open a TUN device.
    ///
    /// Requires CAP_NET_ADMIN or root.
    #[cfg(target_os = "linux")]
    pub fn create(name: &str) -> Result<Self, TunError> {
        use std::ffi::CString;

        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_cstr = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid device name"))?;
        let name_bytes = name_cstr.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
        }
        ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF as libc::Ioctl, &ifr as *const libc::ifreq) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TunError::Io(io::Error::last_os_error()));
        }

        let actual_name = unsafe {
            std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            unsafe { libc::close(fd) };
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TunError::Io(io::Error::last_os_error()));
        }

        Ok(TunDevice {
            fd,
            name: actual_name,
        })
    }

    /// Create and open a utun device (macOS).
    ///
    /// `name` can be "utun" (kernel picks number), "utun5" (requests unit 5), etc.
    /// macOS kernel always assigns the actual name - use `name()` to get it.
    ///
    /// Requires root.
    #[cfg(target_os = "macos")]
    pub fn create(name: &str) -> Result<Self, TunError> {
        // Parse unit number from name: "utun" -> 0 (kernel picks), "utun5" -> 6 (sc_unit = N+1)
        let unit: u32 = if name == "utun" {
            0 // kernel picks
        } else if let Some(num_str) = name.strip_prefix("utun") {
            let n: u32 = num_str
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid utun number"))?;
            n + 1 // sc_unit is 1-based: utun0 -> sc_unit=1
        } else {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "macOS TUN name must start with 'utun'",
            )));
        };

        const SYSPROTO_CONTROL: libc::c_int = 2;
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }

        #[repr(C)]
        struct CtlInfo {
            ctl_id: u32,
            ctl_name: [u8; 96],
        }

        let mut info: CtlInfo = unsafe { std::mem::zeroed() };
        let utun_control = b"com.apple.net.utun_control";
        info.ctl_name[..utun_control.len()].copy_from_slice(utun_control);

        // CTLIOCGINFO = _IOWR('N', 3, struct ctl_info)
        // struct ctl_info is 100 bytes (4 + 96)
        // _IOWR('N', 3, 100) = 0xc0644e03
        const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
        let ret = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TunError::Io(err));
        }

        #[repr(C)]
        struct SockaddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            sc_reserved: [u32; 5],
        }

        const AF_SYSTEM: u8 = libc::AF_SYSTEM as u8;
        const AF_SYS_CONTROL: u16 = 2;

        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TunError::Io(err));
        }

        const UTUN_OPT_IFNAME: libc::c_int = 2;
        let mut ifname_buf = [0u8; libc::IFNAMSIZ];
        let mut ifname_len: libc::socklen_t = ifname_buf.len() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr() as *mut libc::c_void,
                &mut ifname_len,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TunError::Io(err));
        }

        let actual_name = unsafe {
            std::ffi::CStr::from_ptr(ifname_buf.as_ptr() as *const libc::c_char)
                .to_string_lossy()
                .into_owned()
        };

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            unsafe { libc::close(fd) };
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TunError::Io(io::Error::last_os_error()));
        }

        tracing::info!("Created macOS utun device: {}", actual_name);

        Ok(TunDevice {
            fd,
            name: actual_name,
        })
    }

    /// Create a TUN device using wintun (Windows).
    ///
    /// `name` is the adapter display name (e.g. "Redpill VPN").
    /// Requires Administrator privileges.
    #[cfg(target_os = "windows")]
    pub fn create(name: &str) -> Result<Self, TunError> {
        use std::sync::Arc;

        let wintun = unsafe { wintun::load() }.map_err(|e| {
            TunError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("wintun load: {e}"),
            ))
        })?;

        let adapter = wintun::Adapter::create(&wintun, name, "Redpill VPN", None).map_err(|e| {
            TunError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("wintun adapter: {e}"),
            ))
        })?;

        // Ring buffer capacity: 4 MB (good for burst absorption)
        let session = adapter.start_session(0x400000).map_err(|e| {
            TunError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("wintun session: {e}"),
            ))
        })?;

        let actual_name = adapter.get_name().unwrap_or_else(|_| name.to_string());
        tracing::info!("Created wintun adapter: {}", actual_name);

        Ok(TunDevice {
            session: Arc::new(session),
            name: actual_name,
        })
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the MTU on this device.
    #[cfg(target_os = "linux")]
    pub fn set_mtu(&self, mtu: u32) -> Result<(), TunError> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
            ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        }

        let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as libc::Ioctl, &ifr) };
        unsafe { libc::close(sock) };
        if ret < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Set the MTU on this device (macOS - via ifconfig).
    #[cfg(target_os = "macos")]
    pub fn set_mtu(&self, mtu: u32) -> Result<(), TunError> {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "mtu", &mtu.to_string()])
            .output()?;
        if !output.status.success() {
            return Err(TunError::Io(io::Error::other(format!(
                "ifconfig mtu failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))));
        }
        Ok(())
    }

    /// Set the MTU on this device (Windows - via netsh).
    #[cfg(target_os = "windows")]
    pub fn set_mtu(&self, mtu: u32) -> Result<(), TunError> {
        let output = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &self.name,
                &format!("mtu={mtu}"),
                "store=active",
            ])
            .output()?;
        if !output.status.success() {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "netsh mtu failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            )));
        }
        Ok(())
    }

    /// Get the raw file descriptor (Unix only - for AsyncFd).
    #[cfg(unix)]
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Read a single IP packet (blocking).
    ///
    /// On Linux, reads raw IP packets directly.
    /// On macOS, strips the 4-byte AF header that utun prepends.
    #[cfg(target_os = "linux")]
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(TunError::Io(err));
        }
        Ok(n as usize)
    }

    /// Read a single IP packet (blocking) - macOS version.
    ///
    /// macOS utun prepends a 4-byte protocol header (AF_INET/AF_INET6).
    /// Uses readv to split header and payload into separate buffers (zero-alloc).
    #[cfg(target_os = "macos")]
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let mut hdr = [0u8; 4];
        let iov = [
            libc::iovec {
                iov_base: hdr.as_mut_ptr() as *mut libc::c_void,
                iov_len: 4,
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];
        let n = unsafe { libc::readv(self.fd, iov.as_ptr(), 2) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(TunError::Io(err));
        }
        let total = n as usize;
        if total <= 4 {
            return Ok(0);
        }
        Ok(total - 4)
    }

    /// Write a single IP packet (blocking).
    ///
    /// On Linux, writes raw IP packets directly.
    /// On macOS, prepends the 4-byte AF_INET header that utun expects.
    #[cfg(target_os = "linux")]
    pub fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(TunError::Io(err));
        }
        Ok(n as usize)
    }

    /// Write a single IP packet (blocking) - macOS version.
    ///
    /// macOS utun expects a 4-byte protocol header in network byte order (big-endian).
    /// Uses writev to send header + payload without copying (zero-alloc).
    #[cfg(target_os = "macos")]
    pub fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        let af: u32 = if !buf.is_empty() && (buf[0] >> 4) == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };
        let af_bytes = af.to_be_bytes();

        let iov = [
            libc::iovec {
                iov_base: af_bytes.as_ptr() as *mut libc::c_void,
                iov_len: 4,
            },
            libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];
        let n = unsafe { libc::writev(self.fd, iov.as_ptr(), 2) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(TunError::Io(err));
        }
        let written = n as usize;
        Ok(written.saturating_sub(4))
    }

    /// Read a single IP packet (blocking) - Windows wintun version.
    ///
    /// Wintun provides raw IP packets without any header.
    /// Blocks until a packet is available.
    #[cfg(target_os = "windows")]
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        match self.session.receive_blocking() {
            Ok(packet) => {
                let data = packet.bytes();
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            Err(e) => Err(TunError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("wintun recv: {e}"),
            ))),
        }
    }

    /// Write a single IP packet (blocking) - Windows wintun version.
    #[cfg(target_os = "windows")]
    pub fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        let mut packet = self
            .session
            .allocate_send_packet(buf.len() as u16)
            .map_err(|e| {
                TunError::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("wintun alloc: {e}"),
                ))
            })?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Ok(buf.len())
    }

    /// Get the wintun session handle for async I/O (Windows only).
    ///
    /// On Windows, use `tokio::task::spawn_blocking` with `read_packet()` / `write_packet()`
    /// since wintun uses a ring buffer (not a file descriptor).
    #[cfg(target_os = "windows")]
    pub fn session(&self) -> &std::sync::Arc<wintun::Session> {
        &self.session
    }
}

#[cfg(unix)]
impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(unix)]
impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
