use memflow::os::process::*;
use memflow::prelude::v1::*;

use libc::{iovec, pid_t, sysconf, _SC_IOV_MAX};
use std::ffi::c_void;

#[derive(Clone, Copy)]
#[repr(transparent)]
struct IoSendVec(iovec);

unsafe impl Send for IoSendVec {}

#[derive(Clone)]
pub struct ProcessVirtualMemory {
    pid: pid_t,
    temp_iov: Box<[IoSendVec]>,
}

impl ProcessVirtualMemory {
    pub fn new(info: &ProcessInfo) -> Self {
        let iov_max = unsafe { sysconf(_SC_IOV_MAX) } as usize;

        Self {
            pid: info.pid as pid_t,
            temp_iov: vec![
                IoSendVec {
                    0: iovec {
                        iov_base: std::ptr::null_mut::<c_void>(),
                        iov_len: 0
                    }
                };
                iov_max * 2
            ]
            .into_boxed_slice(),
        }
    }

    fn vm_error() -> Option<ErrorKind> {
        let ret = match unsafe { *libc::__errno_location() } {
            libc::EFAULT => return None,
            libc::EINVAL => ErrorKind::ArgValidation,
            libc::ENOMEM => return None,
            libc::EPERM => ErrorKind::NotSupported, // ErrorKind::Permissions
            libc::ESRCH => ErrorKind::ProcessNotFound,
            _ => ErrorKind::Unknown,
        };

        Some(ret)
    }
}

// Helper trait for `process_rw` to be generic.
trait RWSlice: core::ops::Deref<Target = [u8]> {
    /// Pass the iovecs to appropriate system call.
    unsafe fn do_rw(
        pid: pid_t,
        iov_local: *const iovec,
        iov_remote: *const iovec,
        cnt: usize,
    ) -> isize;

    /// Convert local iovec to itself.
    unsafe fn from_iovec(liov: iovec) -> Self;
}

impl<'a> RWSlice for CSliceRef<'a, u8> {
    unsafe fn do_rw(
        pid: pid_t,
        iov_local: *const iovec,
        iov_remote: *const iovec,
        cnt: usize,
    ) -> isize {
        libc::process_vm_writev(pid, iov_local, cnt as _, iov_remote, cnt as _, 0)
    }

    unsafe fn from_iovec(liov: iovec) -> Self {
        core::slice::from_raw_parts(liov.iov_base as *const _, liov.iov_len as usize).into()
    }
}

impl<'a> RWSlice for CSliceMut<'a, u8> {
    unsafe fn do_rw(
        pid: pid_t,
        iov_local: *const iovec,
        iov_remote: *const iovec,
        cnt: usize,
    ) -> isize {
        libc::process_vm_readv(pid, iov_local, cnt as _, iov_remote, cnt as _, 0)
    }

    unsafe fn from_iovec(liov: iovec) -> Self {
        core::slice::from_raw_parts_mut(liov.iov_base as *mut _, liov.iov_len as usize).into()
    }
}

impl ProcessVirtualMemory {
    /// Generic read/write implementation for linux.
    fn process_rw<'a, T: RWSlice>(
        &mut self,
        mut data: CIterator<MemData<Address, T>>,
        out_fail: &mut OpaqueCallback<'a, MemData<Address, T>>,
    ) -> Result<()> {
        let max_iov = self.temp_iov.len() / 2;
        let (iov_local, iov_remote) = self.temp_iov.split_at_mut(max_iov);

        let mut iov_iter = iov_local.iter_mut().zip(iov_remote.iter_mut()).enumerate();
        let mut iov_next = iov_iter.next();

        let mut elem = data.next();

        'exit: while let Some(MemData(a, b)) = elem {
            let (cnt, (liov, riov)) = iov_next.unwrap();

            let iov_len = b.len();

            liov.0 = iovec {
                iov_base: b.as_ptr() as *mut c_void,
                iov_len,
            };

            riov.0 = iovec {
                iov_base: a.to_umem() as *mut c_void,
                iov_len,
            };

            iov_next = iov_iter.next();
            elem = data.next();

            if elem.is_none() || iov_next.is_none() {
                let mut offset = 0;

                // Process all iovecs, but skip one by one if we get partial results
                loop {
                    let cnt = cnt + 1 - offset;

                    if cnt == 0 {
                        break;
                    }

                    let libcret = unsafe {
                        T::do_rw(
                            self.pid,
                            iov_local.as_ptr().add(offset).cast(),
                            iov_remote.as_ptr().add(offset).cast(),
                            cnt,
                        )
                    };

                    let vm_err = if libcret == -1 {
                        Self::vm_error()
                    } else {
                        None
                    };

                    match vm_err {
                        Some(err) => Err(Error(ErrorOrigin::OsLayer, err))?,
                        _ => {
                            let mut remaining_written = libcret as usize + 1;

                            let mut addoff1 = 0;

                            let iter = iov_local
                                .iter()
                                .take(cnt)
                                .enumerate()
                                .zip(iov_remote.iter())
                                .skip_while(|((_, a), _)| {
                                    remaining_written =
                                        remaining_written.saturating_sub(a.0.iov_len);
                                    addoff1 += 1;
                                    remaining_written > 0
                                });

                            let mut addoff2 = 0;

                            // This will take only the first unread element and write it to the
                            // failed list, because it could be that only it is invalid.
                            for ((i, liov), riov) in iter.take(1) {
                                addoff2 = i;
                                if !out_fail
                                    .call(MemData(Address::from(riov.0.iov_base as umem), unsafe {
                                        T::from_iovec(liov.0)
                                    }))
                                {
                                    break 'exit;
                                }
                            }

                            offset += core::cmp::max(addoff1, addoff2);
                        }
                    }
                }

                iov_iter = iov_local.iter_mut().zip(iov_remote.iter_mut()).enumerate();
                iov_next = iov_iter.next();
            }
        }

        Ok(())
    }
}

impl MemoryView for ProcessVirtualMemory {
    fn read_raw_iter<'a>(
        &mut self,
        data: CIterator<ReadData<'a>>,
        out_fail: &mut ReadFailCallback<'_, 'a>,
    ) -> Result<()> {
        self.process_rw(data, out_fail)
    }

    fn write_raw_iter<'a>(
        &mut self,
        data: CIterator<WriteData<'a>>,
        out_fail: &mut WriteFailCallback<'_, 'a>,
    ) -> Result<()> {
        self.process_rw(data, out_fail)
    }

    fn metadata(&self) -> MemoryViewMetadata {
        MemoryViewMetadata {
            arch_bits: if cfg!(pointer_width = "64") { 64 } else { 32 },
            little_endian: cfg!(target_endianess = "little"),
            max_address: Address::invalid(),
            readonly: false,
            real_size: 0,
        }
    }
}
