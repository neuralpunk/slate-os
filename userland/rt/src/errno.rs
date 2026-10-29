// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error numbers (values from musl `bits/errno.h`, ADR 0009) and Slate's
//! own wording for them.

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Errno(pub i32);

macro_rules! errnos {
    ($($name:ident = $v:expr, $msg:expr;)*) => {
        impl Errno {
            $(pub const $name: Errno = Errno($v);)*
            /// A short description of the error.
            pub fn message(self) -> &'static str {
                match self.0 {
                    $($v => $msg,)*
                    _ => "Unknown error",
                }
            }
        }
    };
}

errnos! {
    EPERM = 1, "Operation not permitted";
    ENOENT = 2, "No such file or directory";
    ESRCH = 3, "No such process";
    EINTR = 4, "Interrupted system call";
    EIO = 5, "I/O error";
    ENXIO = 6, "No such device or address";
    E2BIG = 7, "Argument list too long";
    ENOEXEC = 8, "Exec format error";
    EBADF = 9, "Bad file descriptor";
    ECHILD = 10, "No child processes";
    EAGAIN = 11, "Resource temporarily unavailable";
    ENOMEM = 12, "Out of memory";
    EACCES = 13, "Permission denied";
    EFAULT = 14, "Bad address";
    EBUSY = 16, "Resource busy";
    EEXIST = 17, "File exists";
    EXDEV = 18, "Cross-device link";
    ENODEV = 19, "No such device";
    ENOTDIR = 20, "Not a directory";
    EISDIR = 21, "Is a directory";
    EINVAL = 22, "Invalid argument";
    ENFILE = 23, "Too many open files in system";
    EMFILE = 24, "Too many open files";
    ENOTTY = 25, "Inappropriate ioctl for device";
    EFBIG = 27, "File too large";
    ENOSPC = 28, "No space left on device";
    ESPIPE = 29, "Illegal seek";
    EROFS = 30, "Read-only file system";
    EMLINK = 31, "Too many links";
    EPIPE = 32, "Broken pipe";
    EDOM = 33, "Numerical argument out of domain";
    ERANGE = 34, "Result out of range";
    EDEADLK = 35, "Resource deadlock avoided";
    ENAMETOOLONG = 36, "File name too long";
    ENOSYS = 38, "Function not implemented";
    ENOTEMPTY = 39, "Directory not empty";
    ELOOP = 40, "Too many levels of symbolic links";
    ENOTSOCK = 88, "Not a socket";
    EOPNOTSUPP = 95, "Operation not supported";
    EAFNOSUPPORT = 97, "Address family not supported";
    ENETUNREACH = 101, "Network is unreachable";
    ECONNRESET = 104, "Connection reset by peer";
    ETIMEDOUT = 110, "Timed out";
    ECONNREFUSED = 111, "Connection refused";
    EHOSTUNREACH = 113, "No route to host";
    EINPROGRESS = 115, "Operation in progress";
    // Slate's own (slate_abi::error, ADR 0032).
    LINUX_OFF = 200, "Linux program: Linux compatibility mode is off (turn it on with slate-compat on)";
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Errno({}: {})", self.0, self.message())
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

pub type Result<T> = core::result::Result<T, Errno>;
