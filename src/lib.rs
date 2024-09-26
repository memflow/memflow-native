#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxOs as NativeOs;
#[cfg(target_os = "linux")]
pub use linux::LinuxProcess as NativeProcess;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOs as NativeOs;
#[cfg(target_os = "macos")]
pub use macos::MacProcess as NativeProcess;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::WindowsKeyboard as NativeKeyboard;
#[cfg(target_os = "windows")]
pub use self::windows::WindowsKeyboardState as NativeKeyboardState;
#[cfg(target_os = "windows")]
pub use self::windows::WindowsOs as NativeOs;
#[cfg(target_os = "windows")]
pub use self::windows::WindowsProcess as NativeProcess;
#[cfg(target_os = "windows")]
use crate::keyboard::OsKeyboardVtbl;

use memflow::cglue;
use memflow::prelude::v1::*;

#[cfg(target_os = "windows")]
cglue_impl_group!(NativeOs, OsInstance, { OsKeyboard });
#[cfg(not(target_os = "windows"))]
cglue_impl_group!(NativeOs, OsInstance, {});

#[cfg_attr(feature = "plugins", os(name = "native", return_wrapped = true))]
pub fn create_os(args: &OsArgs, lib: LibArc) -> Result<OsInstanceArcBox<'static>> {
    let os = NativeOs::new(args)?;
    Ok(memflow::plugins::os::create_instance(os, lib, args))
}
