use memflow::cglue;
use memflow::os::keyboard::*;
use memflow::prelude::v1::*;

use windows::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, GetKeyboardState};

#[derive(Default, Clone)]
pub struct WindowsKeyboard {}

cglue_impl_group!(WindowsKeyboard, IntoKeyboard);

impl WindowsKeyboard {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Keyboard for WindowsKeyboard {
    type KeyboardStateType = WindowsKeyboardState;

    /// Returns true wether the given key was pressed.
    /// This function accepts a valid microsoft virtual keycode.
    /// In case of supplying a invalid key this function will just return false cleanly.
    ///
    /// A list of all Keycodes can be found on the [msdn](https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes).
    fn is_down(&mut self, vk: i32) -> bool {
        let key_state = unsafe { GetKeyState(vk) };
        key_state as u16 & 0x8000 != 0
    }

    fn set_down(&mut self, _vk: i32, _down: bool) {
        // TODO:
    }

    /// Reads the entire keyboard state.
    fn state(&mut self) -> memflow::error::Result<Self::KeyboardStateType> {
        let mut buffer = [0u8; 256];
        unsafe { GetKeyboardState(&mut buffer) }.map_err(|_| {
            Error(ErrorOrigin::Connector, ErrorKind::NotFound)
                .log_error("unable to read keyboard state")
        })?;
        Ok(WindowsKeyboardState { buffer })
    }
}

/// Represents the current Keyboardstate.
#[derive(Clone)]
pub struct WindowsKeyboardState {
    buffer: [u8; 256],
}

impl KeyboardState for WindowsKeyboardState {
    /// Returns true wether the given key was pressed.
    /// This function accepts a valid microsoft virtual keycode.
    /// In case of supplying a invalid key this function will just return false cleanly.
    ///
    /// A list of all Keycodes can be found on the [msdn](https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes).
    fn is_down(&self, vk: i32) -> bool {
        if (0..=256).contains(&vk) {
            self.buffer[vk as usize] & 0x80 != 0
        } else {
            false
        }
    }
}
