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
    temp_meta: Box<[Address]>,
}

impl ProcessVirtualMemory {
    pub fn new(info: &ProcessInfo) -> Self {
        let iov_max = unsafe { sysconf(_SC_IOV_MAX) } as usize;

        Self {
            pid: info.pid as pid_t,
            temp_iov: vec![
                IoSendVec(iovec {
                    iov_base: std::ptr::null_mut::<c_void>(),
                    iov_len: 0
                });
                iov_max * 2
            ]
            .into_boxed_slice(),
            temp_meta: vec![Address::INVALID; iov_max].into_boxed_slice(),
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
        #[allow(clippy::unnecessary_cast)]
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
        #[allow(clippy::unnecessary_cast)]
        core::slice::from_raw_parts_mut(liov.iov_base as *mut _, liov.iov_len as usize).into()
    }
}

impl ProcessVirtualMemory {
    /// Generic read/write implementation for linux.
    fn process_rw<T: RWSlice>(
        &mut self,
        MemOps {
            mut inp,
            mut out,
            mut out_fail,
        }: MemOps<CTup3<Address, Address, T>, CTup2<Address, T>>,
    ) -> Result<()> {
        let max_iov = self.temp_iov.len() / 2;
        let (iov_local, iov_remote) = self.temp_iov.split_at_mut(max_iov);

        let mut iov_iter = iov_local
            .iter_mut()
            .zip(iov_remote.iter_mut().zip(self.temp_meta.iter_mut()))
            .enumerate();
        let mut iov_next = iov_iter.next();

        let mut elem = inp.next();

        'exit: while let Some(CTup3(a, m, b)) = elem {
            let (cnt, (liov, (riov, meta))) = iov_next.unwrap();

            let iov_len = b.len();

            liov.0 = iovec {
                iov_base: b.as_ptr() as *mut c_void,
                iov_len,
            };

            riov.0 = iovec {
                iov_base: a.to_umem() as *mut c_void,
                iov_len,
            };

            *meta = m;

            iov_next = iov_iter.next();
            elem = inp.next();

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
                        Some(err) => return Err(Error(ErrorOrigin::OsLayer, err)),
                        _ => {
                            let mut remaining_written = libcret as usize + 1;

                            for (liof, (_, meta)) in iov_local
                                .iter()
                                .take(cnt)
                                .zip(iov_remote.iter().zip(self.temp_meta.iter()))
                            {
                                offset += 1;
                                let to_write = remaining_written;

                                remaining_written =
                                    remaining_written.saturating_sub(liof.0.iov_len);

                                if to_write > 0 {
                                    if !opt_call(
                                        out.as_deref_mut(),
                                        CTup2(*meta, unsafe { T::from_iovec(liof.0) }),
                                    ) {
                                        break 'exit;
                                    }
                                } else {
                                    // This will take only the first unread element and write it to the
                                    // failed list, because it could be that only it is invalid.
                                    if !opt_call(
                                        out_fail.as_deref_mut(),
                                        CTup2(*meta, unsafe { T::from_iovec(liof.0) }),
                                    ) {
                                        break 'exit;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                iov_iter = iov_local
                    .iter_mut()
                    .zip(iov_remote.iter_mut().zip(self.temp_meta.iter_mut()))
                    .enumerate();
                iov_next = iov_iter.next();
            }
        }

        Ok(())
    }
}

impl MemoryView for ProcessVirtualMemory {
    fn read_raw_iter<'a>(&mut self, data: ReadRawMemOps) -> Result<()> {
        self.process_rw(data)
    }

    fn write_raw_iter<'a>(&mut self, data: WriteRawMemOps) -> Result<()> {
        self.process_rw(data)
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
