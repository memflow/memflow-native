use memflow::os::process::*;
use memflow::prelude::v1::*;

use libc::pid_t;
use log::error;

use procfs::KernelModule;

use itertools::Itertools;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub mod keyboard;
mod keymap;
pub use keyboard::{LinuxKeyboard, LinuxKeyboardState};

pub mod mem;
use mem::ProcessVirtualMemory;

pub mod process;
use process::process_state;
pub use process::LinuxProcess;

/// Architecture of the host the backend is running on.
///
/// memflow-native works through native syscalls, so the inspected processes always run
/// under the same kernel/ISA as this build. We therefore report the compile target's
/// architecture rather than assuming x86-64. 32-bit processes running under a 64-bit
/// kernel are still reported as 64-bit here; distinguishing them would require sniffing
/// the ELF class of `/proc/<pid>/exe`.
fn host_arch() -> ArchitectureIdent {
    #[cfg(target_arch = "x86_64")]
    {
        ArchitectureIdent::X86(64, false)
    }
    #[cfg(target_arch = "x86")]
    {
        ArchitectureIdent::X86(32, false)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Page size is read at runtime; only 4k is currently supported by memflow.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        ArchitectureIdent::AArch64(if page_size > 0 {
            page_size as usize
        } else {
            0x1000
        })
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        ArchitectureIdent::Unknown(0)
    }
}

/// Stable, ordering-independent handle for a kernel module, derived from its name.
/// `procfs::KernelModule` exposes no kernel address we could reuse, so hashing the name
/// keeps the handle valid across module load/unload churn (unlike a list index).
///
/// `DefaultHasher` is fixed-seeded (unlike the randomized `RandomState` behind
/// `HashMap`), so the handle is consistent across the two lookups within a process run,
/// which is all this handle needs.
fn module_handle(name: &str) -> Address {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    Address::from(hasher.finish())
}

pub struct LinuxOs {
    info: OsInfo,
}

impl LinuxOs {
    pub fn new(_: &OsArgs) -> Result<Self> {
        Ok(Default::default())
    }

    fn kernel_modules_sorted(&self) -> Result<Vec<KernelModule>> {
        let mut modules: Vec<KernelModule> = procfs::modules()
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?
            .into_values()
            .collect();
        modules.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(modules)
    }
}

impl Clone for LinuxOs {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
        }
    }
}

impl Default for LinuxOs {
    fn default() -> Self {
        let info = OsInfo {
            base: Address::NULL,
            size: 0,
            arch: host_arch(),
        };

        Self { info }
    }
}

impl Os for LinuxOs {
    type ProcessType<'a> = LinuxProcess;
    type IntoProcessType = LinuxProcess;

    /// Walks a process list and calls a callback for each process structure address
    ///
    /// The callback is fully opaque. We need this style so that C FFI can work seamlessly.
    fn process_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        procfs::process::all_processes()
            .map_err(|e| {
                error!("{e}");
                Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir)
            })?
            .filter_map(|p| p.map(|p| p.pid() as usize).ok())
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
        let proc = procfs::process::Process::new(pid as pid_t)
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?;

        let command_line = proc
            .cmdline()
            .ok()
            .map(|v| v.join(" ").split('\0').collect_vec().join(" "))
            .unwrap_or_else(String::new)
            .into();

        let path = proc
            .cmdline()
            .ok()
            .and_then(|l| {
                l.first()
                    .map(|s| s.split('\0').next().unwrap_or("").to_string())
            })
            .unwrap_or_else(|| {
                proc.status()
                    .ok()
                    .map(|s| s.name)
                    .unwrap_or_else(|| "unknown".to_string())
            });

        let name = path.split(&['/', '\\'][..]).last().unwrap().into();

        let path = path.into();

        let arch = host_arch();

        Ok(ProcessInfo {
            address: (proc.pid() as umem).into(),
            pid,
            command_line,
            path,
            name,
            sys_arch: arch,
            proc_arch: arch,
            state: process_state(pid as pid_t),
            // dtb is not known/used here
            dtb1: Address::invalid(),
            dtb2: Address::invalid(),
        })
    }

    /// Construct a process by its info, borrowing the OS
    ///
    /// It will share the underlying memory resources
    fn process_by_info(&mut self, info: ProcessInfo) -> Result<Self::ProcessType<'_>> {
        LinuxProcess::try_new(info)
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
        let modules = self.kernel_modules_sorted()?;

        modules
            .iter()
            .map(|km| module_handle(&km.name))
            .take_while(|a| callback.call(*a))
            .for_each(|_| {});

        Ok(())
    }

    /// Retrieves a module by its structure address
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    fn module_by_address(&mut self, address: Address) -> Result<ModuleInfo> {
        let modules = self.kernel_modules_sorted()?;

        modules
            .iter()
            .find(|km| module_handle(&km.name) == address)
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
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    /// Retrieves address of the primary module structure of the process
    ///
    /// This will generally be for the initial executable that was run
    fn primary_module_address(&mut self) -> Result<Address> {
        // TODO: Add Linux kernel image discovery via /proc/kallsyms and/or /sys/kernel/sections.
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported))
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

impl OsKeyboard for LinuxOs {
    type KeyboardType<'a> = LinuxKeyboard;
    type IntoKeyboardType = LinuxKeyboard;

    fn keyboard(&mut self) -> Result<Self::KeyboardType<'_>> {
        LinuxKeyboard::new()
    }

    fn into_keyboard(self) -> Result<Self::IntoKeyboardType> {
        LinuxKeyboard::new()
    }
}
