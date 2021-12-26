#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxOs as NativeOs;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::WindowsOs as NativeOs;

use memflow::cglue;
use memflow::prelude::v1::*;

cglue_impl_group!(NativeOs, OsInstance, {});

#[os_layer_bare(name = "native")]
pub fn build_os(
    _args: &OsArgs,
    _: Option<ConnectorInstanceArcBox<'static>>,
    lib: CArc<std::ffi::c_void>,
) -> Result<OsInstanceArcBox<'static>> {
    log::info!("Initialize native OS!");
    Ok(group_obj!((NativeOs::default(), lib) as OsInstance))
}
