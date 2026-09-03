use memflow::cglue;
use memflow::os::keyboard::*;
use memflow::prelude::v1::*;

use windows::Win32::Foundation::GetLastError;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, GetKeyboardState, MapVirtualKeyW, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD,
    INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
    MAPVK_VK_TO_VSC, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
};

// `XBUTTON1`/`XBUTTON2` live in `Win32_UI_WindowsAndMessaging`; inline them rather than
// pulling in that whole feature for two constants.
const XBUTTON1: u32 = 1;
const XBUTTON2: u32 = 2;

/// Virtual-key codes whose scancodes live in the extended range; `SendInput` needs
/// `KEYEVENTF_EXTENDEDKEY` for these so consumers can tell them apart from their
/// base-key twins (e.g. arrow keys vs. numpad arrows, right ctrl vs. left ctrl).
fn is_extended_key(vk: i32) -> bool {
    matches!(
        vk,
        0x21..=0x28 // VK_PRIOR, VK_NEXT, VK_END, VK_HOME, arrow keys
        | 0x2C..=0x2E // VK_SNAPSHOT, VK_INSERT, VK_DELETE
        | 0x5B..=0x5D // VK_LWIN, VK_RWIN, VK_APPS
        | 0x6F // VK_DIVIDE
        | 0x90 // VK_NUMLOCK
        | 0xA3 // VK_RCONTROL
        | 0xA5 // VK_RMENU
    )
}

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

    /// Presses or releases the given key via `SendInput`. Mouse button virtual-key
    /// codes are injected as mouse input, everything else as keyboard input. Invalid
    /// keycodes are ignored cleanly; injection failures are logged, as this interface
    /// has no error channel.
    fn set_down(&mut self, vk: i32, down: bool) {
        if !(0..=0xFF).contains(&vk) {
            return;
        }

        let input = match vk {
            // VK_LBUTTON, VK_RBUTTON, VK_MBUTTON, VK_XBUTTON1, VK_XBUTTON2
            0x01 | 0x02 | 0x04 | 0x05 | 0x06 => {
                let (flags, data) = match (vk, down) {
                    (0x01, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (0x01, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (0x02, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (0x02, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (0x04, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (0x04, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (0x05, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
                    (0x05, false) => (MOUSEEVENTF_XUP, XBUTTON1),
                    (0x06, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
                    (0x06, false) => (MOUSEEVENTF_XUP, XBUTTON2),
                    _ => unreachable!(),
                };
                INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dx: 0,
                            dy: 0,
                            mouseData: data,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            }
            _ => {
                let mut flags = KEYBD_EVENT_FLAGS(0);
                if !down {
                    flags |= KEYEVENTF_KEYUP;
                }
                if is_extended_key(vk) {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(vk as u16),
                            // Fill in the scancode so consumers reading scancodes
                            // (DirectInput / raw input) see the key as well.
                            wScan: unsafe { MapVirtualKeyW(vk as u32, MAPVK_VK_TO_VSC) } as u16,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            }
        };

        if unsafe { SendInput(&[input], core::mem::size_of::<INPUT>() as i32) } == 0 {
            log::warn!(
                "unable to inject input event for vk {vk:#x}: {:?}",
                unsafe { GetLastError() }
            );
        }
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
        if (0..256).contains(&vk) {
            self.buffer[vk as usize] & 0x80 != 0
        } else {
            false
        }
    }
}
