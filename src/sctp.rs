// SCTP association wrapper with Linux multistream support
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use socket2::Socket;

/// One-to-one SCTP association wrapper
/// Linux uses sctp_sendmsg/sctp_recvmsg for stream ids
pub struct SctpAssociation {
    // Owned socket2 handle
    socket: Socket,
}

impl SctpAssociation {
    /// Wrap connected SCTP socket
    pub fn new(socket: Socket) -> Self {
        Self { socket }
    }

    /// Expose raw fd
    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Borrow inner socket
    pub fn inner(&self) -> &Socket {
        &self.socket
    }

    /// Take inner socket
    pub fn into_inner(self) -> Socket {
        self.socket
    }

    /// Send message on SCTP stream id
    pub fn send(&self, stream_id: u16, buf: &[u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            // True multistream send
            unsafe { linux::sctp_send(self.socket.as_raw_fd(), stream_id, buf) }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Fallback write without stream ids
            use std::io::Write;
            let mut f = &self.socket;
            f.write(buf)
        }
    }

    /// Receive one SCTP message
    /// Returns (bytes, stream_id)
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u16)> {
        #[cfg(target_os = "linux")]
        {
            // True multistream recv
            unsafe { linux::sctp_recv(self.socket.as_raw_fd(), buf) }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Fallback read with stream_id=0
            use std::io::Read;
            let mut f = &self.socket;
            let n = f.read(buf)?;
            Ok((n, 0))
        }
    }
}

impl AsRawFd for SctpAssociation {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

// Linux SCTP FFI bindings
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use libc::{c_int, c_void};

    // libsctp symbols
    #[link(name = "sctp")]
    extern "C" {
        fn sctp_sendmsg(
            sd: c_int,
            msg: *const c_void,
            len: usize,
            to: *const libc::sockaddr,
            tolen: libc::socklen_t,
            ppid: u32,
            flags: u32,
            stream_no: u16,
            timetolive: u32,
            context: u32,
        ) -> c_int;

        fn sctp_recvmsg(
            sd: c_int,
            msg: *mut c_void,
            len: usize,
            from: *mut libc::sockaddr,
            fromlen: *mut libc::socklen_t,
            sinfo: *mut SctpSndRcvInfo,
            msg_flags: *mut c_int,
        ) -> c_int;
    }

    /// Minimal sctp_sndrcvinfo clone
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct SctpSndRcvInfo {
        pub sinfo_stream: u16,
        pub sinfo_ssn: u16,
        pub sinfo_flags: u16,
        pub sinfo_ppid: u32,
        pub sinfo_context: u32,
        pub sinfo_timetolive: u32,
        pub sinfo_tsn: u32,
        pub sinfo_cumtsn: u32,
        pub sinfo_assoc_id: i32,
    }

    /// Linux send with stream id
    pub unsafe fn sctp_send(fd: RawFd, stream_id: u16, buf: &[u8]) -> io::Result<usize> {
        let ret = sctp_sendmsg(
            fd,
            buf.as_ptr() as *const c_void,
            buf.len(),
            std::ptr::null(),
            0,
            0,
            0,
            stream_id,
            0,
            0,
        );
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Linux recv with extracted stream id
    pub unsafe fn sctp_recv(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, u16)> {
        let mut sinfo: SctpSndRcvInfo = std::mem::zeroed();
        let mut msg_flags: c_int = 0;

        let ret = sctp_recvmsg(
            fd,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sinfo as *mut SctpSndRcvInfo,
            &mut msg_flags as *mut c_int,
        );

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok((ret as usize, sinfo.sinfo_stream))
    }
}