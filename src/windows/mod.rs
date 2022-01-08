use memflow::os::process::*;
use memflow::prelude::v1::*;

use windows::Win32::Foundation::{CloseHandle, HANDLE, PSTR};

use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};

use core::mem::{size_of, MaybeUninit};
use core::ptr;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub mod mem;
use mem::ProcessVirtualMemory;

pub mod process;
use process::WindowsProcess;

struct KernelModule {}

pub(crate) struct Handle(HANDLE);

impl From<HANDLE> for Handle {
    fn from(handle: HANDLE) -> Handle {
        Handle(handle)
    }
}

impl core::ops::Deref for Handle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub fn conv_err(_err: windows::core::Error) -> Error {
    // TODO: proper error kind
    // TODO: proper origin
    Error(ErrorOrigin::OsLayer, ErrorKind::Unknown)
}

unsafe fn enable_debug_privilege() -> Result<()> {
    let process = GetCurrentProcess();
    let mut token = HANDLE(0);

    OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &mut token)
        .ok()
        .map_err(conv_err)?;

    let mut luid = Default::default();

    let mut se_debug_name = *b"SeDebugPrivilege\0";

    LookupPrivilegeValueA(
        PSTR(core::ptr::null_mut()),
        PSTR(se_debug_name.as_mut_ptr()),
        &mut luid,
    )
    .ok()
    .map_err(conv_err)?;

    let new_privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    AdjustTokenPrivileges(
        token,
        false,
        &new_privileges,
        std::mem::size_of_val(&new_privileges) as _,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    )
    .ok()
    .map_err(conv_err)
}

pub struct WindowsOs {
    info: OsInfo,
    cached_processes: Vec<ProcessInfo>,
    cached_modules: Vec<KernelModule>,
}

impl WindowsOs {
    pub fn new(args: &OsArgs) -> Result<Self> {
        match args.extra_args.get("elevate_token") {
            Some("off") | Some("OFF") | Some("Off") | Some("n") | Some("N") | Some("0") => {}
            _ => {
                unsafe { enable_debug_privilege() }?;
            }
        }

        Ok(Default::default())
    }
}

impl Clone for WindowsOs {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            cached_processes: vec![],
            cached_modules: vec![],
        }
    }
}

impl Default for WindowsOs {
    fn default() -> Self {
        let info = OsInfo {
            base: Address::NULL,
            size: 0,
            arch: ArchitectureIdent::X86(64, false),
        };

        Self {
            info,
            cached_modules: vec![],
            cached_processes: vec![],
        }
    }
}

impl<'a> OsInner<'a> for WindowsOs {
    type ProcessType = WindowsProcess;
    type IntoProcessType = WindowsProcess;

    /// Walks a process list and calls a callback for each process structure address
    ///
    /// The callback is fully opaque. We need this style so that C FFI can work seamlessly.
    fn process_address_list_callback(&mut self, callback: AddressCallback) -> Result<()> {
        let handle = Handle(
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
                .ok()
                .map_err(conv_err)?,
        );

        let mut maybe_entry = MaybeUninit::<PROCESSENTRY32W>::uninit();

        unsafe {
            ptr::write(
                &mut (*maybe_entry.as_mut_ptr()).dwSize,
                size_of::<PROCESSENTRY32W>() as u32,
            );
        }

        let ptr = maybe_entry.as_mut_ptr();

        std::iter::once(unsafe { Process32FirstW(*handle, ptr) })
            .chain(std::iter::repeat_with(|| unsafe {
                Process32NextW(*handle, ptr)
            }))
            .take_while(|b| b.as_bool())
            .map(|_| unsafe { maybe_entry.assume_init() })
            .map(|p| {
                let address = Address::from(p.th32ProcessID as umem);
                let len = p.szExeFile.iter().take_while(|&&c| c != 0).count();

                let path = OsString::from_wide(&p.szExeFile[..len]);
                let path = path.to_string_lossy();
                let path = &*path;
                let name = path.rsplit_once("\\").map(|(_, end)| end).unwrap_or(path);

                self.cached_processes.push(ProcessInfo {
                    address,
                    pid: address.to_umem() as _,
                    state: ProcessState::Alive,
                    name: name.into(),
                    path: path.into(),
                    command_line: "".into(),
                    sys_arch: self.info.arch,
                    proc_arch: self.info.arch,
                });

                address
            })
            .feed_into(callback);

        Ok(())
    }

    /// Find process information by its internal address
    fn process_info_by_address(&mut self, address: Address) -> Result<ProcessInfo> {
        self.cached_processes
            .iter()
            .find(|p| p.address == address)
            .cloned()
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    /// Construct a process by its info, borrowing the OS
    ///
    /// It will share the underlying memory resources
    fn process_by_info(&'a mut self, info: ProcessInfo) -> Result<Self::ProcessType> {
        WindowsProcess::try_new(info)
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
        /*self.cached_modules = procfs::modules()
        .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?
        .into_iter()
        .map(|(_, v)| v)
        .collect();*/

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
    fn module_by_address(&mut self, _address: Address) -> Result<ModuleInfo> {
        /*self.cached_modules
        .iter()
        .skip(address.to_umem() as usize)
        .next()
        .map(|km| ModuleInfo {
            address,
            size: km.size as umem,
            base: Address::NULL,
            name: km
                .name
                .split("/")
                .last()
                .or(Some(""))
                .map(ReprCString::from)
                .unwrap(),
            arch: self.info.arch,
            path: km.name.clone().into(),
            parent_process: Address::INVALID,
        })
        .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))*/

        todo!()
    }

    /// Retrieves the OS info
    fn info(&self) -> &OsInfo {
        &self.info
    }
}
