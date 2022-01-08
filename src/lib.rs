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

#[cfg_attr(feature = "plugins", os_layer_bare(name = "native"))]
pub fn build_os(
    args: &OsArgs,
    _: Option<ConnectorInstanceArcBox<'static>>,
    lib: LibArc,
) -> Result<OsInstanceArcBox<'static>> {
    log::info!("Initialize native OS!");
    Ok(group_obj!((NativeOs::new(args)?, lib) as OsInstance))
}
