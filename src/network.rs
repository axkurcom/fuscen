// Socket helpers for UDP and SCTP
use std::io;
use std::net::{SocketAddr, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::constants::{IPPROTO_SCTP, OPTIMAL_BUFFER_SIZE};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Common socket configuration
pub struct SocketConfig {
    // OS buffers
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,

    // Nonblocking flag
    pub nonblocking: bool,

    // Reuse flags
    pub reuse_addr: bool,
    pub reuse_port: bool,

    // Optional UDP zero-copy
    pub zero_copy: bool,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            send_buffer_size: OPTIMAL_BUFFER_SIZE,
            recv_buffer_size: OPTIMAL_BUFFER_SIZE,
            nonblocking: false,
            reuse_addr: true,
            reuse_port: false,
            zero_copy: false,
        }
    }
}

/// Create and bind UDP socket
pub fn create_udp_socket(addr: SocketAddr, config: &SocketConfig) -> io::Result<UdpSocket> {
    // Pick IP family
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, None)?;

    // Basic options
    if config.reuse_addr {
        socket.set_reuse_address(true)?;
    }

    if config.reuse_port {
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
    }

    // Buffer sizes and mode
    socket.set_recv_buffer_size(config.recv_buffer_size)?;
    socket.set_send_buffer_size(config.send_buffer_size)?;
    socket.set_nonblocking(config.nonblocking)?;

    // Best-effort zero-copy
    #[cfg(unix)]
    if config.zero_copy && supports_zero_copy() {
        enable_zero_copy(socket.as_raw_fd())?;
    }

    socket.bind(&addr.into())?;

    Ok(socket.into())
}

/// Create SCTP one-to-one listener
pub fn create_sctp_listener(port: u16, config: &SocketConfig) -> io::Result<Socket> {
    // SOCK_STREAM + IPPROTO_SCTP
    let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;

    if config.reuse_addr {
        listener.set_reuse_address(true)?;
    }

    // Buffers and mode
    listener.set_recv_buffer_size(config.recv_buffer_size)?;
    listener.set_send_buffer_size(config.send_buffer_size)?;
    listener.set_nonblocking(config.nonblocking)?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    listener.bind(&bind_addr.into())?;
    listener.listen(1024)?;

    Ok(listener)
}

/// Create SCTP client socket and connect
/// Nonblocking connect may return EINPROGRESS
pub fn create_sctp_client(server_addr: SocketAddr, config: &SocketConfig) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;

    socket.set_send_buffer_size(config.send_buffer_size)?;
    socket.set_recv_buffer_size(config.recv_buffer_size)?;
    socket.set_nonblocking(config.nonblocking)?;

    let addr = server_addr.into();

    match socket.connect(&addr) {
        Ok(()) => Ok(socket),
        Err(e) => {
            // Allow in-progress connect in nonblocking mode
            if config.nonblocking {
                if let Some(code) = e.raw_os_error() {
                    if code == libc::EINPROGRESS || code == libc::EWOULDBLOCK {
                        return Ok(socket);
                    }
                }
            }
            Err(e)
        }
    }
}

/// Try increase UDP buffers to a reasonable max
pub fn optimize_socket_buffers(socket: &UdpSocket) -> io::Result<()> {
    let socket2_socket = Socket::from(socket.try_clone()?);
    let max_buffer = 4 * 1024 * 1024;

    // Best-effort recv size
    for size in &[max_buffer, 2 * 1024 * 1024, 1 * 1024 * 1024, 512 * 1024] {
        if socket2_socket.set_recv_buffer_size(*size).is_ok() {
            break;
        }
    }

    // Best-effort send size
    for size in &[max_buffer, 2 * 1024 * 1024, 1 * 1024 * 1024, 512 * 1024] {
        if socket2_socket.set_send_buffer_size(*size).is_ok() {
            break;
        }
    }

    Ok(())
}

/// Detect OS support for UDP zero-copy
pub fn supports_zero_copy() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::fs;

        // Parse kernel version from procfs
        if let Ok(kernel_version) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = kernel_version.trim().split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>())
                {
                    // UDP zerocopy requires 4.14+
                    return major > 4 || (major == 4 && minor >= 14);
                }
            }
        }
    }
    false
}

/// Enable SO_ZEROCOPY if possible
#[cfg(unix)]
fn enable_zero_copy(fd: i32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let enable: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ZEROCOPY,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };

        if result == 0 {
            println!("[✓] Zero-copy enabled for socket");
            Ok(())
        } else {
            // Non-fatal
            println!("[⚠] Failed to enable zero-copy: {}", io::Error::last_os_error());
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Non-linux no-op
        println!("[⚠] Zero-copy not supported on this platform");
        Ok(())
    }
}