use memflow::os::process::*;
use memflow::prelude::v1::*;

use libc::pid_t;
use log::error;

use procfs::KernelModule;

use itertools::Itertools;

pub mod mem;
use mem::ProcessVirtualMemory;

pub mod process;
use process::LinuxProcess;

pub struct LinuxOs {
    info: OsInfo,
    cached_modules: Vec<KernelModule>,
}

impl LinuxOs {
    pub fn new(_: &OsArgs) -> Result<Self> {
        Ok(Default::default())
    }
}

impl Clone for LinuxOs {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            cached_modules: vec![],
        }
    }
}

impl Default for LinuxOs {
    fn default() -> Self {
        let info = OsInfo {
            base: Address::NULL,
            size: 0,
            arch: ArchitectureIdent::X86(64, false),
        };

        Self {
            info,
            cached_modules: vec![],
        }
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
            .into_iter()
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
                l.get(0)
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

        Ok(ProcessInfo {
            address: (proc.pid() as umem).into(),
            pid,
            command_line,
            path,
            name,
            sys_arch: ArchitectureIdent::X86(64, false),
            proc_arch: ArchitectureIdent::X86(64, false),
            state: ProcessState::Alive,
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
        self.cached_modules = procfs::modules()
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?
            .into_values()
            .collect();

        (0..self.cached_modules.len())
            .map(Address::from)
            .take_while(|a| callback.call(*a))
            .for_each(|_| {});

        Ok(())
    }

    /// Retrieves a module by its structure address
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    fn module_by_address(&mut self, address: Address) -> Result<ModuleInfo> {
        self.cached_modules
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
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
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
