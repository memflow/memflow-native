use memflow::os::process::*;
use memflow::prelude::v1::*;

use libc::{c_int, size_t, sysctl, CTL_KERN, KERN_ARGMAX, KERN_PROCARGS2};

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
pub use process::MacProcess;

#[derive(Clone, Debug, Default)]
pub(super) struct ProcArgs {
    pub exec_path: String,
    pub argv: Vec<String>,
    #[cfg(memflow_plugin_api = "2")]
    pub environ: Vec<(String, String)>,
}

fn argmax() -> usize {
    let mut mib: [c_int; 2] = [CTL_KERN, KERN_ARGMAX];
    let mut value: c_int = 0;
    let mut len = core::mem::size_of::<c_int>() as size_t;

    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            (&mut value as *mut c_int).cast(),
            &mut len,
            core::ptr::null_mut(),
            0,
        )
    };

    if ret == 0 && value > 0 {
        value as usize
    } else {
        4096
    }
}

pub(super) fn read_procargs2(pid: Pid) -> Result<Vec<u8>> {
    // Read raw `KERN_PROCARGS2` for the target pid.
    // This is shared by process-info building and env/argv enumeration to keep parsing consistent.
    let mut scratch = vec![0u8; argmax()];

    let mut mib: [c_int; 3] = [CTL_KERN, KERN_PROCARGS2, pid as _];
    let mut len = scratch.len() as size_t;

    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            scratch.as_mut_ptr().cast(),
            &mut len,
            core::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 || len < 4 {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
    }

    scratch.truncate(len);
    Ok(scratch)
}

#[cfg(memflow_plugin_api = "2")]
fn parse_environ(buf: &[u8]) -> Vec<(String, String)> {
    let mut environ = Vec::new();
    let mut idx = 0;

    while idx < buf.len() {
        let start = idx;
        while idx < buf.len() && buf[idx] != 0 {
            idx += 1;
        }

        if idx == start {
            break;
        }

        let entry = String::from_utf8_lossy(&buf[start..idx]);
        if let Some((name, value)) = entry.split_once('=') {
            environ.push((name.to_string(), value.to_string()));
        }

        if idx < buf.len() {
            idx += 1;
        }
    }

    environ
}

pub(super) fn parse_procargs2(data: &[u8]) -> Result<ProcArgs> {
    if data.len() < 4 {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
    }

    let mut argc_buf = [0u8; 4];
    argc_buf.copy_from_slice(&data[..4]);
    let argc = u32::from_ne_bytes(argc_buf) as usize;
    let buf = &data[4..];

    let mut idx = 0usize;
    while idx < buf.len() && buf[idx] != 0 {
        idx += 1;
    }
    if idx == buf.len() {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
    }

    let exec_path = String::from_utf8_lossy(&buf[..idx]).into_owned();

    while idx < buf.len() && buf[idx] == 0 {
        idx += 1;
    }

    let mut argv = Vec::new();
    for _ in 0..argc {
        if idx >= buf.len() {
            break;
        }
        let start = idx;
        while idx < buf.len() && buf[idx] != 0 {
            idx += 1;
        }
        if idx > start {
            argv.push(String::from_utf8_lossy(&buf[start..idx]).into_owned());
        }
        if idx < buf.len() {
            idx += 1;
        }
    }

    Ok(ProcArgs {
        exec_path,
        argv,
        #[cfg(memflow_plugin_api = "2")]
        environ: parse_environ(&buf[idx..]),
    })
}

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
        // We query BSD info with the target `pid`.
        // Using the caller pid here breaks name-based filtering.
        let bsd_info =
            lp::proc_pid::pidinfo::<lp::bsd_info::BSDInfo>(pid as _, 0).map_err(|e| {
                error!("bsd_info: {e}");
                Error(ErrorOrigin::OsLayer, ErrorKind::Unknown)
            })?;

        // We could use lp::proc_pid::pidpath for path, but we already get it from procargs2
        let (path, command_line): (ReprCString, ReprCString) = {
            let fallback_path = bsd_info
                .pbi_comm
                .iter()
                .copied()
                .map(|b| b as u8)
                .take_while(|b| *b != 0)
                .collect::<Vec<u8>>();
            let fallback_path = String::from_utf8_lossy(&fallback_path).into_owned();

            // Prefer parsed procargs for executable path + argv, but always keep a safe fallback.
            match read_procargs2(pid).and_then(|d| parse_procargs2(&d)) {
                Ok(parsed) => {
                    let path = if parsed.exec_path.is_empty() {
                        fallback_path.as_str()
                    } else {
                        parsed.exec_path.as_str()
                    };
                    (path.into(), parsed.argv.join(" ").into())
                }
                Err(_) => (fallback_path.into(), "".into()),
            }
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
    fn module_address_list_callback(&mut self, _callback: AddressCallback) -> Result<()> {
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
    fn module_by_address(&mut self, _address: Address) -> Result<ModuleInfo> {
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
