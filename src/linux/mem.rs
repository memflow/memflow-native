use memflow::os::process::*;
use memflow::prelude::v1::*;

use libc::{iovec, pid_t, sysconf, _SC_IOV_MAX};
use std::ffi::c_void;

#[derive(Clone, Copy)]
#[repr(transparent)]
struct IoSendVec(iovec);

// Safety: IoSendVec stores transient iovec pointers that are only constructed and
// consumed within &mut self operations; no cross-thread aliasing is exposed.
unsafe impl Send for IoSendVec {}

#[derive(Clone)]
pub struct ProcessVirtualMemory {
    pid: pid_t,
    temp_iov: Box<[IoSendVec]>,
    temp_meta: Box<[Address]>,
}

impl ProcessVirtualMemory {
    pub fn new(info: &ProcessInfo) -> Self {
        const DEFAULT_IOV_MAX: usize = 1024;

        let iov_max = usize::try_from(unsafe { sysconf(_SC_IOV_MAX) })
            .ok()
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_IOV_MAX);

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
            let Some((cnt, (liov, (riov, meta)))) = iov_next else {
                debug_assert!(
                    false,
                    "iov_next must exist while current input element is present"
                );
                break;
            };

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
                            let mut remaining_written =
                                if libcret == -1 { 0 } else { libcret as usize };

                            // The syscall above operated on the window [win, win + cnt),
                            // so result dispatch and byte accounting must start at `win`
                            // too. `offset` is advanced inside the loop, so snapshot it
                            // before iterating.
                            let win = offset;

                            for (liof, (_, meta)) in iov_local.iter().skip(win).take(cnt).zip(
                                iov_remote
                                    .iter()
                                    .skip(win)
                                    .zip(self.temp_meta.iter().skip(win)),
                            ) {
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
            arch_bits: if cfg!(target_pointer_width = "64") {
                64
            } else {
                32
            },
            little_endian: cfg!(target_endian = "little"),
            max_address: Address::invalid(),
            readonly: false,
            real_size: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memflow::cglue::CTup2;

    fn vmem_for_pid(pid: pid_t) -> ProcessVirtualMemory {
        const IOV_MAX: usize = 1024;
        ProcessVirtualMemory {
            pid,
            temp_iov: vec![
                IoSendVec(iovec {
                    iov_base: std::ptr::null_mut::<c_void>(),
                    iov_len: 0,
                });
                IOV_MAX * 2
            ]
            .into_boxed_slice(),
            temp_meta: vec![Address::INVALID; IOV_MAX].into_boxed_slice(),
        }
    }

    // Regression test for the partial-transfer retry window in `process_rw`.
    //
    // A batched read of [valid, unmapped, valid] forces `process_vm_readv` to transfer
    // the first region, fault on the middle one, and require a retry for the third.
    // Before the `.skip(win)` fix the retry dispatched from index 0, re-reporting the
    // first region and silently dropping the third. Reading from our own PID lets us
    // exercise this without spawning a child.
    #[test]
    fn partial_read_across_hole_reports_each_region_once() {
        let src_a = [0xAAu8; 8];
        let src_c = [0xCCu8; 8];

        let addr_a = Address::from(src_a.as_ptr() as u64);
        let addr_c = Address::from(src_c.as_ptr() as u64);
        // Below the default mmap_min_addr, so reliably unmapped (EFAULT on read).
        let addr_bad = Address::from(0x1000u64);

        let mut dst_a = [0u8; 8];
        let mut dst_b = [0u8; 8];
        let mut dst_c = [0u8; 8];

        let mut ok: Vec<(Address, Vec<u8>)> = Vec::new();
        let mut fail: Vec<Address> = Vec::new();

        {
            let inp = vec![
                CTup2(addr_a, (&mut dst_a[..]).into()),
                CTup2(addr_bad, (&mut dst_b[..]).into()),
                CTup2(addr_c, (&mut dst_c[..]).into()),
            ];

            let mut ok_cb = |CTup2(a, d): ReadData| {
                ok.push((a, d.to_vec()));
                true
            };
            let mut fail_cb = |CTup2(a, _): ReadData| {
                fail.push(a);
                true
            };
            let mut ok_oc: ReadCallback = (&mut ok_cb).into();
            let mut fail_oc: ReadCallback = (&mut fail_cb).into();

            let mut mem = vmem_for_pid(unsafe { libc::getpid() });
            mem.read_iter(inp.into_iter(), Some(&mut ok_oc), Some(&mut fail_oc))
                .unwrap();
        }

        ok.sort_by_key(|(a, _)| a.to_umem());
        let mut expected = vec![(addr_a, vec![0xAAu8; 8]), (addr_c, vec![0xCCu8; 8])];
        expected.sort_by_key(|(a, _)| a.to_umem());

        assert_eq!(
            ok, expected,
            "each readable region must be reported exactly once with correct data"
        );
        assert_eq!(
            fail,
            vec![addr_bad],
            "the unmapped region must be the only failure"
        );
    }
}
