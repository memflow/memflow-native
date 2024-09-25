use memflow::os::process::*;
use memflow::prelude::v1::*;

use core::ffi::c_void;

use mach2::{
    kern_return::KERN_SUCCESS,
    port::{mach_port_t, MACH_PORT_NULL},
    traps::{mach_task_self, task_for_pid},
    vm::{mach_vm_read_overwrite, mach_vm_write},
};

fn get_task(pid: u32) -> Result<mach_port_t> {
    unsafe {
        let mut task = MACH_PORT_NULL;
        let res = task_for_pid(mach_task_self(), pid as i32, &mut task as *mut mach_port_t);
        if res != KERN_SUCCESS {
            log::error!("Could not get task: {res}");
            Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown))
        } else {
            Ok(task)
        }
    }
}

#[derive(Clone)]
pub struct ProcessVirtualMemory {
    pub(crate) port: mach_port_t,
    pid: u32,
}

impl ProcessVirtualMemory {
    pub fn try_new(info: &ProcessInfo) -> Result<Self> {
        Ok(Self {
            port: get_task(info.pid)?,
            pid: info.pid,
        })
    }
}

// Helper trait for `process_rw` to be generic.
trait RWSlice: core::ops::Deref<Target = [u8]> {
    /// Call the appropriate system call.
    unsafe fn do_rw(
        port: mach_port_t,
        local: *const c_void,
        remote: *const c_void,
        size: usize,
    ) -> Result<usize>;
}

impl<'a> RWSlice for CSliceRef<'a, u8> {
    unsafe fn do_rw(
        port: mach_port_t,
        local: *const c_void,
        remote: *const c_void,
        size: usize,
    ) -> Result<usize> {
        // For some reason this function only accepts u32 as size, meaning >4g writes will fail. So
        // fix this by chunking.
        #[cfg(target_pointer_width = "64")]
        let iter = (0..size).step_by(1 << 32);
        #[cfg(target_pointer_width = "32")]
        let iter = core::iter::once(0);

        let mut written = 0;

        for off in iter {
            let size = core::cmp::min(size - off, u32::MAX as _);

            let ret = mach_vm_write(port, remote as _, local as _, size as u32);

            if ret != KERN_SUCCESS {
                if written == 0 {
                    return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
                } else {
                    break;
                }
            }

            written += size;
        }

        Ok(written)
    }
}

impl<'a> RWSlice for CSliceMut<'a, u8> {
    unsafe fn do_rw(
        port: mach_port_t,
        local: *const c_void,
        remote: *const c_void,
        size: usize,
    ) -> Result<usize> {
        // mach_vm_read_list exists, however, it seems to allocate new buffers, meaning, we would
        // need to perform a second copy, and free those buffers immediately afterwards (1 syscall
        // per buffer!). Therefore, we are doing sequential read syscall per buffer.
        let ret = mach_vm_read_overwrite(port, remote as _, size as _, local as _, &mut 0);
        if ret != KERN_SUCCESS {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadMemory));
        }
        Ok(size)
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
            let written =
                unsafe { T::do_rw(self.port, buf.as_ptr() as _, addr.to_umem() as _, buf.len()) }
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
