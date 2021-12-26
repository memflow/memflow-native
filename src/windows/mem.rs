use memflow::os::process::*;
use memflow::prelude::v1::*;

use std::ffi::c_void;
use std::sync::Arc;

use super::{conv_err, Handle};

use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

#[derive(Clone)]
pub struct ProcessVirtualMemory {
    pub(crate) handle: Arc<Handle>,
}

impl ProcessVirtualMemory {
    pub fn try_new(info: &ProcessInfo) -> Result<Self> {
        let handle: Arc<Handle> = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false,
                info.pid as _,
            )
        }
        .ok()
        .map_err(conv_err)
        .map(Handle::from)?
        .into();

        Ok(Self { handle })
    }

    fn vm_error() -> Option<ErrorKind> {
        let ret = /*match unsafe { *libc::__errno_location() } {
            libc::EFAULT => return None,
            libc::EINVAL => ErrorKind::ArgValidation,
            libc::ENOMEM => return None,
            libc::EPERM => ErrorKind::NotSupported, // ErrorKind::Permissions
            libc::ESRCH => ErrorKind::ProcessNotFound,
            _ => ErrorKind::Unknown,
        };*/ ErrorKind::Unknown;

        Some(ret)
    }
}

// Helper trait for `process_rw` to be generic.
trait RWSlice: core::ops::Deref<Target = [u8]> {
    /// Call the appropriate system call.
    unsafe fn do_rw(
        handle: &Handle,
        local: *const c_void,
        remote: *const c_void,
        size: usize,
    ) -> Result<usize>;
}

impl<'a> RWSlice for CSliceRef<'a, u8> {
    unsafe fn do_rw(
        handle: &Handle,
        local: *const c_void,
        remote: *const c_void,
        size: usize,
    ) -> Result<usize> {
        let mut written = 0;
        WriteProcessMemory(**handle, remote as _, local, size, &mut written)
            .ok()
            .map_err(conv_err)?;
        Ok(written)
    }
}

impl<'a> RWSlice for CSliceMut<'a, u8> {
    unsafe fn do_rw(
        handle: &Handle,
        local: *const c_void,
        remote: *const c_void,
        size: usize,
    ) -> Result<usize> {
        let mut written = 0;
        WriteProcessMemory(**handle, remote, local as _, size, &mut written)
            .ok()
            .map_err(conv_err)?;
        Ok(written)
    }
}

impl ProcessVirtualMemory {
    /// Generic read/write implementation for linux.
    fn process_rw<'a, T: RWSlice + SplitAtIndex>(
        &mut self,
        mut data: CIterator<MemData<Address, T>>,
        out_fail: &mut OpaqueCallback<'a, MemData<Address, T>>,
    ) -> Result<()> {
        for MemData(addr, buf) in data {
            let written = unsafe {
                T::do_rw(
                    &*self.handle,
                    buf.as_ptr() as _,
                    addr.to_umem() as _,
                    buf.len(),
                )
            }
            .unwrap_or(0);

            if let (_, Some(fail)) = buf.split_at(written as _) {
                if !out_fail.call(MemData(addr + written, fail)) {
                    break;
                }
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
