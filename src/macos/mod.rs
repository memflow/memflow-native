use memflow::os::process::*;
use memflow::prelude::v1::*;

use libc::{c_int, sysctl, CTL_KERN, KERN_PROCARGS2};

use libc::{sysconf, _SC_PAGESIZE};
use libproc::{
    libproc as lp,
    processes::{pids_by_type, ProcFilter},
};

use std::sync::OnceLock;

use log::*;

#[inline]
pub fn page_size() -> usize {
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

pub fn is_rosetta(flags: u32) -> bool {
    (flags & 0x2000000) != 0
}

pub mod mem;
use mem::ProcessVirtualMemory;

pub mod process;
use process::MacProcess;

fn get_arch() -> ArchitectureIdent {
    static ARCH: OnceLock<ArchitectureIdent> = OnceLock::new();

    *ARCH.get_or_init(|| {
        let arm = mac_sys_info::get_mac_sys_info()
            .map(|i| i.cpu_info().architecture().is_apple_si())
            .unwrap_or(true);
        if arm {
            ArchitectureIdent::AArch64(page_size() as _)
        } else {
            ArchitectureIdent::X86(64, false)
        }
    })
}

pub struct MacOs {
    info: OsInfo,
    scratch: Box<[u8]>,
    //cached_modules: Vec<KernelModule>,
}

impl MacOs {
    pub fn new(_: &OsArgs) -> Result<Self> {
        Ok(Default::default())
    }
}

impl Clone for MacOs {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            scratch: self.scratch.clone(),
            //cached_modules: vec![],
        }
    }
}

impl Default for MacOs {
    fn default() -> Self {
        let info = OsInfo {
            base: Address::NULL,
            size: 0,
            arch: get_arch(),
        };

        Self {
            info,
            // TODO: call KERN_ARGMAX to figure out the actual value.
            scratch: vec![0; 4096].into_boxed_slice(),
            //cached_modules: vec![],
        }
    }
}

impl Os for MacOs {
    type ProcessType<'a> = MacProcess;
    type IntoProcessType = MacProcess;

    /// Walks a process list and calls a callback for each process structure address
    ///
    /// The callback is fully opaque. We need this style so that C FFI can work seamlessly.
    fn process_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        pids_by_type(ProcFilter::All)
            .map_err(|e| {
                error!("{e}");
                Error(ErrorOrigin::OsLayer, ErrorKind::Unknown)
            })?
            .into_iter()
            .map(Address::from)
            .take_while(|a| callback.call(*a))
            .for_each(|_| {});

        Ok(())
    }

    /// Find process information by its internal address
    fn process_info_by_address(&mut self, address: Address) -> Result<ProcessInfo> {
        self.process_info_by_pid(address.to_umem() as _)
    }

    fn process_info_by_pid(&mut self, pid: Pid) -> Result<ProcessInfo> {
        let us = std::process::id();

        let bsd_info =
            lp::proc_pid::pidinfo::<lp::bsd_info::BSDInfo>(us as _, pid as _).map_err(|e| {
                error!("bsd_info: {e}");
                Error(ErrorOrigin::OsLayer, ErrorKind::Unknown)
            })?;

        // We could use lp::proc_pid::pidpath for path, but we already get it from procargs2
        let (path, command_line): (ReprCString, ReprCString) = {
            let mut name: [c_int; 3] = [CTL_KERN, KERN_PROCARGS2, pid as _];
            let mut len = self.scratch.len() - 4;
            let ret = unsafe {
                sysctl(
                    name.as_mut_ptr(),
                    name.len() as _,
                    self.scratch.as_mut_ptr().cast(),
                    &mut len,
                    core::ptr::null_mut(),
                    0,
                )
            };

            if ret != 0 {
                len = 0;
            }

            // We skip the first arg, because that is the executable path.
            let mut num_args = u32::from_ne_bytes(self.scratch[..4].try_into().unwrap()) + 1;

            let buf = &mut self.scratch[4..(4 + len)];

            let mut start_idx = 0;
            let mut start_idx_stripped = 0;
            let mut idx = 0;

            for (i, b) in buf.iter_mut().enumerate() {
                if num_args == 0 {
                    break;
                }

                if *b == 0 {
                    *b = b' ';
                    num_args -= 1;
                    if start_idx == 0 {
                        start_idx = i + 1;
                        start_idx_stripped = i + 1;
                    } else if start_idx_stripped == i {
                        num_args += 1;
                        start_idx_stripped = i + 1;
                    }
                }

                idx = i;
            }

            let path = if start_idx == 0 {
                let b = bsd_info.pbi_comm.split(|v| *v == 0).next().unwrap_or(&[]);
                unsafe { &*(b as *const [_] as *const [u8]) }
            } else {
                &buf[..(start_idx - 1)]
            };

            (
                std::str::from_utf8(path).unwrap_or_default().into(),
                std::str::from_utf8(if start_idx_stripped <= idx {
                    &buf[start_idx_stripped..idx]
                } else {
                    &[]
                })
                .unwrap_or_default()
                .into(),
            )
        };
        let name = path.split(&['/', '\\'][..]).last().unwrap().into();

        let path = path.into();

        let ret = Ok(ProcessInfo {
            address: (pid as umem).into(),
            pid,
            command_line,
            path,
            name,
            sys_arch: get_arch(),
            proc_arch: if is_rosetta(bsd_info.pbi_flags) {
                ArchitectureIdent::X86(64, false)
            } else {
                get_arch()
            },
            state: ProcessState::Alive,
            // dtb is not known/used here
            dtb1: Address::invalid(),
            dtb2: Address::invalid(),
        });

        ret
    }

    /// Construct a process by its info, borrowing the OS
    ///
    /// It will share the underlying memory resources
    fn process_by_info(&mut self, info: ProcessInfo) -> Result<Self::ProcessType<'_>> {
        MacProcess::try_new(info)
    }

    /// Construct a process by its info, consuming the OS
    ///
    /// This function will consume the Kernel instance and move its resources into the process
    fn into_process_by_info(mut self, info: ProcessInfo) -> Result<Self::IntoProcessType> {
        self.process_by_info(info)
    }

    /// Walks the OS module list and calls the provided callback for each module structure
    /// address
    ///
    /// # Arguments
    /// * `callback` - where to pass each matching module to. This is an opaque callback.
    fn module_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        // TODO: build this with OSKextCopyLoadedKextInfo.
        /*self.cached_modules = procfs::modules()
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?
            .into_values()
            .collect();

        (0..self.cached_modules.len())
            .map(Address::from)
            .take_while(|a| callback.call(*a))
            .for_each(|_| {});*/

        Ok(())
    }

    /// Retrieves a module by its structure address
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    fn module_by_address(&mut self, address: Address) -> Result<ModuleInfo> {
        /*self.cached_modules
        .get(address.to_umem() as usize)
        .map(|km| ModuleInfo {
            address,
            size: km.size as umem,
            base: Address::NULL,
            name: km
                .name
                .split('/')
                .last()
                .or(Some(""))
                .map(ReprCString::from)
                .unwrap(),
            arch: self.info.arch,
            path: km.name.clone().into(),
            parent_process: Address::INVALID,
        })
        .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))*/
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    /// Retrieves address of the primary module structure of the process
    ///
    /// This will generally be for the initial executable that was run
    fn primary_module_address(&mut self) -> Result<Address> {
        // TODO: Is it always 0th mod?
        Ok(Address::from(0))
    }

    /// Retrieves a list of all imports of a given module
    fn module_import_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: ImportCallback,
    ) -> Result<()> {
        //memflow::os::util::module_import_list_callback(&mut self.virt_mem, info, callback)
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }

    /// Retrieves a list of all exports of a given module
    fn module_export_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: ExportCallback,
    ) -> Result<()> {
        //memflow::os::util::module_export_list_callback(&mut self.virt_mem, info, callback)
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }

    /// Retrieves a list of all sections of a given module
    fn module_section_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: SectionCallback,
    ) -> Result<()> {
        //memflow::os::util::module_section_list_callback(&mut self.virt_mem, info, callback)
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }

    /// Retrieves the OS info
    fn info(&self) -> &OsInfo {
        &self.info
    }
}
