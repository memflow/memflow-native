use memflow::os::process::*;
use memflow::prelude::v1::*;

use std::ffi::c_void;
use std::sync::Arc;

use super::{conv_err, Handle};

use windows::core::HRESULT;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

#[derive(Clone)]
pub struct ProcessVirtualMemory {
    pub(crate) handle: Arc<Handle>,
}

impl ProcessVirtualMemory {
    pub fn try_new(info: &ProcessInfo) -> Result<Self> {
        let handle: Arc<Handle> = unsafe {
            OpenProcess(
                PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_QUERY_INFORMATION,
                false,
                info.pid as _,
            )
        }
        .map_err(conv_err)
        .map(Handle::from)?
        .into();

        Ok(Self { handle })
    }

    #[allow(unused)]
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
        WriteProcessMemory(**handle, remote as _, local, size, Some(&mut written))
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

        match ReadProcessMemory(**handle, remote, local as _, size, Some(&mut written)) {
            Ok(_) => Ok(written),
            Err(err) if err.code() == HRESULT::from_win32(299) => Ok(written), // ERROR_PARTIAL_COPY
            Err(err) => Err(conv_err(err)),
        }
    }
}

impl ProcessVirtualMemory {
    /// Generic read/write implementation for linux.
    fn process_rw<T: RWSlice + SplitAtIndex>(
        &mut self,
        MemOps {
            inp,
            mut out,
            mut out_fail,
        }: MemOps<CTup3<Address, Address, T>, CTup2<Address, T>>,
    ) -> Result<()> {
        for CTup3(addr, meta_addr, buf) in inp {
            let written = unsafe {
                T::do_rw(
                    &self.handle,
                    buf.as_ptr() as _,
                    addr.to_umem() as _,
                    buf.len(),
                )
            }
            .unwrap_or(0);

            let (succeed, fail) = buf.split_at(written as _);

            if let Some(succeed) = succeed {
                if succeed.len() > 0 && !opt_call(out.as_deref_mut(), CTup2(meta_addr, succeed)) {
                    break;
                }
            }

            if let Some(fail) = fail {
                if fail.len() > 0
                    && !opt_call(out_fail.as_deref_mut(), CTup2(meta_addr + written, fail))
                {
                    break;
                }
            }
        }

        Ok(())
    }
}

impl MemoryView for ProcessVirtualMemory {
    fn read_raw_iter(&mut self, data: ReadRawMemOps) -> Result<()> {
        self.process_rw(data)
    }

    fn write_raw_iter(&mut self, data: WriteRawMemOps) -> Result<()> {
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
