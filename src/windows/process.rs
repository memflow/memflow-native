use memflow::cglue;
use memflow::os::process::*;
use memflow::prelude::v1::*;

use super::{conv_err, ProcessVirtualMemory};

use itertools::Itertools;

use windows::Win32::Foundation::{HINSTANCE, PSTR};
use windows::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32GetModuleFileNameExA, K32GetModuleInformation, LIST_MODULES_32BIT,
    LIST_MODULES_64BIT,
};

use core::mem::{size_of, size_of_val};

#[derive(Clone)]
pub struct WindowsProcess {
    virt_mem: ProcessVirtualMemory,
    //proc: procfs::process::Process,
    info: ProcessInfo,
    cached_modules: Vec<HINSTANCE>,
    //cached_maps: Vec<procfs::process::MemoryMap>,
    //cached_module_maps: Vec<procfs::process::MemoryMap>,
}

impl WindowsProcess {
    pub fn try_new(info: ProcessInfo) -> Result<Self> {
        Ok(Self {
            virt_mem: ProcessVirtualMemory::try_new(&info)?,
            info,
            cached_modules: vec![],
        })
    }
}

cglue_impl_group!(WindowsProcess, ProcessInstance, {});
cglue_impl_group!(WindowsProcess, IntoProcessInstance, {});

impl Process for WindowsProcess {
    /// Walks the process' module list and calls the provided callback for each module structure
    /// address
    ///
    /// # Arguments
    /// * `target_arch` - sets which architecture to retrieve the modules for (if emulated). Choose
    /// between `Some(ProcessInfo::sys_arch())`, and `Some(ProcessInfo::proc_arch())`. `None` for all.
    /// * `callback` - where to pass each matching module to. This is an opaque callback.
    fn module_address_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        mut callback: ModuleAddressCallback,
    ) -> Result<()> {
        let filter_flags = match target_arch {
            Some(ident) => match ident.into_obj().bits() {
                32 => [Some(LIST_MODULES_32BIT), None],
                64 => [Some(LIST_MODULES_64BIT), None],
                _ => [Some(LIST_MODULES_32BIT), Some(LIST_MODULES_64BIT)],
            },
            None => [Some(LIST_MODULES_32BIT), Some(LIST_MODULES_64BIT)],
        };

        for f in IntoIterator::into_iter(filter_flags).filter_map(|i| i) {
            self.cached_modules.clear();
            self.cached_modules.resize(1024, 0);

            let mut needed = 0;

            loop {
                unsafe {
                    K32EnumProcessModulesEx(
                        **self.virt_mem.handle,
                        self.cached_modules.as_mut_ptr(),
                        (self.cached_modules.len() * size_of::<HINSTANCE>()) as _,
                        &mut needed,
                        f,
                    )
                    .ok()
                    .map_err(conv_err)?
                }

                if needed as usize <= self.cached_modules.len() {
                    self.cached_modules.resize(needed as _, 0);
                    break;
                }

                self.cached_modules.resize(self.cached_modules.len() * 2, 0);
            }

            // TODO: ARM STUFF
            let arch = match f {
                LIST_MODULES_32BIT => ArchitectureIdent::X86(32, false),
                LIST_MODULES_64BIT => ArchitectureIdent::X86(64, false),
                _ => ArchitectureIdent::Unknown(0),
            };

            callback.extend(self.cached_modules.iter().map(|&m| ModuleAddressInfo {
                address: Address::from(m as umem),
                arch,
            }));
        }

        Ok(())
    }

    /// Retrieves a module by its structure address and architecture
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    /// * `architecture` - architecture of the module. Should be either `ProcessInfo::proc_arch`, or `ProcessInfo::sys_arch`.
    fn module_by_address(
        &mut self,
        address: Address,
        arch: ArchitectureIdent,
    ) -> Result<ModuleInfo> {
        let mut path = [0u8; 128];

        if unsafe {
            K32GetModuleFileNameExA(
                **self.virt_mem.handle,
                address.to_umem() as HINSTANCE,
                PSTR(path.as_mut_ptr() as *mut _),
                path.len() as _,
            )
        } == 0
        {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
        }

        let mut info = Default::default();

        unsafe {
            K32GetModuleInformation(
                **self.virt_mem.handle,
                address.to_umem() as HINSTANCE,
                &mut info,
                size_of_val(&info) as _,
            )
        }
        .ok()
        .map_err(conv_err)?;

        let path = String::from_utf8_lossy(&path);
        let path = &*path;
        let path = path.split_once('\0').map(|(i, _)| i).unwrap_or(path);
        let name = path.rsplit_once('\\').map(|(_, i)| i).unwrap_or(path);

        Ok(ModuleInfo {
            address,
            parent_process: self.info.address,
            arch,
            base: address,
            size: info.SizeOfImage as _,
            name: name.into(),
            path: path.into(),
        })
    }

    fn module_import_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ImportCallback,
    ) -> Result<()> {
        memflow::os::util::module_import_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_export_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ExportCallback,
    ) -> Result<()> {
        memflow::os::util::module_export_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_section_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: SectionCallback,
    ) -> Result<()> {
        memflow::os::util::module_section_list_callback(&mut self.virt_mem, info, callback)
    }

    /// Retrieves address of the primary module structure of the process
    ///
    /// This will generally be for the initial executable that was run
    fn primary_module_address(&mut self) -> Result<Address> {
        // TODO: Is it always 0th mod?
        Ok(Address::from(0))
    }

    /// Retrieves the process info
    fn info(&self) -> &ProcessInfo {
        &self.info
    }

    /// Retrieves the state of the process
    fn state(&mut self) -> ProcessState {
        ProcessState::Unknown
    }

    fn mapped_mem_range(
        &mut self,
        gap_size: imem,
        start: Address,
        end: Address,
        out: MemoryRangeCallback,
    ) {
        //todo!()
    }
}

impl MemoryView for WindowsProcess {
    fn read_raw_iter<'a>(
        &mut self,
        data: CIterator<ReadData<'a>>,
        out_fail: &mut ReadFailCallback<'_, 'a>,
    ) -> Result<()> {
        self.virt_mem.read_raw_iter(data, out_fail)
    }

    fn write_raw_iter<'a>(
        &mut self,
        data: CIterator<WriteData<'a>>,
        out_fail: &mut WriteFailCallback<'_, 'a>,
    ) -> Result<()> {
        self.virt_mem.write_raw_iter(data, out_fail)
    }

    fn metadata(&self) -> MemoryViewMetadata {
        self.virt_mem.metadata()
    }
}
