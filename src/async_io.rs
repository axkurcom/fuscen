// Minimal epoll/kqueue wrapper for fd readiness
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(target_os = "linux")]
use libc::{
    epoll_create1, epoll_ctl, epoll_event, epoll_wait, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT,
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
use libc::{kevent, kqueue, EV_ADD, EV_DELETE, EV_EOF, EV_ERROR, EV_ENABLE, EVFILT_READ, EVFILT_WRITE};

/// OS-specific poller handle
pub struct AsyncIO {
    // Linux epoll fd
    #[cfg(target_os = "linux")]
    epoll_fd: RawFd,

    // BSD kqueue fd
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    kq_fd: RawFd,
}

impl AsyncIO {
    /// Create poller
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let epoll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
            if epoll_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { epoll_fd })
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            let kq_fd = unsafe { kqueue() };
            if kq_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { kq_fd })
        }
    }

    /// Register fd in epoll
    #[cfg(target_os = "linux")]
    pub fn add_fd(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        let mut event = epoll_event { events: 0, u64: token };

        if read {
            event.events |= EPOLLIN as u32;
        }
        if write {
            event.events |= EPOLLOUT as u32;
        }

        let res = unsafe { epoll_ctl(self.epoll_fd, EPOLL_CTL_ADD, fd, &mut event) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Modify epoll interest set
    #[cfg(target_os = "linux")]
    pub fn modify_fd(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        let mut event = epoll_event { events: 0, u64: token };

        if read {
            event.events |= EPOLLIN as u32;
        }
        if write {
            event.events |= EPOLLOUT as u32;
        }

        let res = unsafe { epoll_ctl(self.epoll_fd, EPOLL_CTL_MOD, fd, &mut event) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Register fd in kqueue
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub fn add_fd(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        let mut changelist = Vec::new();

        if read {
            changelist.push(libc::kevent {
                ident: fd as usize,
                filter: EVFILT_READ,
                flags: EV_ADD | EV_ENABLE,
                fflags: 0,
                data: 0,
                udata: token as *mut _,
            });
        }

        if write {
            changelist.push(libc::kevent {
                ident: fd as usize,
                filter: EVFILT_WRITE,
                flags: EV_ADD | EV_ENABLE,
                fflags: 0,
                data: 0,
                udata: token as *mut _,
            });
        }

        let res = unsafe {
            kevent(
                self.kq_fd,
                changelist.as_ptr(),
                changelist.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };

        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wait for events on epoll
    #[cfg(target_os = "linux")]
    pub fn wait(&self, timeout_ms: i32) -> io::Result<Vec<Event>> {
        // Fixed max batch
        let mut events = vec![unsafe { std::mem::zeroed::<epoll_event>() }; 1024];

        let count = unsafe {
            epoll_wait(self.epoll_fd, events.as_mut_ptr(), events.len() as i32, timeout_ms)
        };

        if count < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let event = events[i];
            let mut ev = Event {
                token: event.u64,
                readable: (event.events & (EPOLLIN as u32)) != 0,
                writable: (event.events & (EPOLLOUT as u32)) != 0,
                error: (event.events & ((EPOLLERR | EPOLLHUP) as u32)) != 0,
            };

            // Normalize error events
            if ev.error {
                ev.readable = false;
                ev.writable = false;
            }

            result.push(ev);
        }

        Ok(result)
    }

    /// Wait for events on kqueue
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub fn wait(&self, timeout_ms: i32) -> io::Result<Vec<Event>> {
        let mut eventlist = vec![unsafe { std::mem::zeroed::<libc::kevent>() }; 1024];

        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let timeout_ptr: *const libc::timespec = if timeout_ms < 0 {
            std::ptr::null()
        } else {
            ts.tv_sec = (timeout_ms / 1000) as libc::time_t;
            ts.tv_nsec = ((timeout_ms % 1000) * 1_000_000) as libc::c_long;
            &ts as *const libc::timespec
        };

        let count = unsafe {
            kevent(
                self.kq_fd,
                std::ptr::null(),
                0,
                eventlist.as_mut_ptr(),
                eventlist.len() as i32,
                timeout_ptr,
            )
        };

        if count < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let event = eventlist[i];
            let token = event.udata as u64;

            let mut ev = Event {
                token,
                readable: event.filter == EVFILT_READ,
                writable: event.filter == EVFILT_WRITE,
                error: (event.flags & EV_ERROR) != 0 || (event.flags & EV_EOF) != 0,
            };

            // Treat EOF on read as error+readable
            if (event.flags & EV_EOF) != 0 && event.filter == EVFILT_READ {
                ev.readable = true;
                ev.error = true;
            }

            result.push(ev);
        }

        Ok(result)
    }

    /// Remove fd from poller
    pub fn remove_fd(&self, fd: RawFd) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let res = unsafe { epoll_ctl(self.epoll_fd, EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            let changelist = [
                libc::kevent {
                    ident: fd as usize,
                    filter: EVFILT_READ,
                    flags: EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
                libc::kevent {
                    ident: fd as usize,
                    filter: EVFILT_WRITE,
                    flags: EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
            ];

            let res = unsafe {
                kevent(
                    self.kq_fd,
                    changelist.as_ptr(),
                    changelist.len() as i32,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };

            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

impl Drop for AsyncIO {
    /// Close poller fd
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::close(self.epoll_fd);
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        unsafe {
            libc::close(self.kq_fd);
        }
    }
}

/// Normalized readiness event
#[derive(Debug, Clone)]
pub struct Event {
    pub token: u64,
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
}

/// Async tuning placeholder
pub struct AsyncSocketConfig {
    pub read_timeout_ms: i32,
    pub write_timeout_ms: i32,
    pub max_events_per_poll: usize,
}

impl Default for AsyncSocketConfig {
    fn default() -> Self {
        Self {
            read_timeout_ms: 1000,
            write_timeout_ms: 1000,
            max_events_per_poll: 1024,
        }
    }
}

/// Set O_NONBLOCK on fd
pub fn setup_async_socket<T: AsRawFd>(socket: &T, nonblocking: bool) -> io::Result<()> {
    // No-op if blocking
    if !nonblocking {
        return Ok(());
    }

    let fd = socket.as_raw_fd();

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Compile-time platform support check
pub fn check_async_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        true
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        let kq = unsafe { kqueue() };
        if kq < 0 {
            false
        } else {
            unsafe { libc::close(kq) };
            true
        }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    {
        false
    }
}