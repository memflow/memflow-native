use memflow::cglue;
use memflow::os::keyboard::*;
use memflow::prelude::v1::*;

use std::sync::{Arc, Mutex};

use evdev::{Device, EventType, KeyCode};

use super::keymap::vk_to_keycodes;

/// Number of bits in the key state bitset, covering evdev codes `0..=KEY_MAX` (0x2ff).
const KEY_STATE_BITS: usize = 0x300;
const KEY_STATE_WORDS: usize = KEY_STATE_BITS / 64;

/// Keyboard state reader backed by evdev (`/dev/input/event*`).
///
/// Key state is polled via the `EVIOCGKEY` ioctl (the analog of Windows'
/// `GetKeyboardState`), which reads the currently-pressed key bitmap without consuming
/// input events. Requires read access to the device nodes, i.e. root or membership in
/// the `input` group.
///
/// Devices are enumerated once on construction. Devices that disappear (unplug) are
/// dropped on the fly, and a full re-enumeration is attempted whenever none of the
/// cached devices remain readable; keyboards plugged in while cached devices still work
/// are not picked up.
#[derive(Clone)]
pub struct LinuxKeyboard {
    devices: Arc<Mutex<Vec<Device>>>,
}

cglue_impl_group!(LinuxKeyboard, IntoKeyboard);

impl LinuxKeyboard {
    pub fn new() -> Result<Self> {
        let devices = Self::enumerate_devices();

        if devices.is_empty() {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound).log_error(
                "no readable keyboard devices in /dev/input (requires root or membership in the 'input' group)",
            ));
        }

        Ok(Self {
            devices: Arc::new(Mutex::new(devices)),
        })
    }

    fn enumerate_devices() -> Vec<Device> {
        evdev::enumerate()
            .filter_map(|(path, device)| {
                if Self::is_key_input_device(&device) {
                    Some(device)
                } else {
                    log::debug!("skipping non-keyboard input device {}", path.display());
                    None
                }
            })
            .collect()
    }

    /// Accepts keyboards (identified by a representative set of keys, which weeds out
    /// power buttons and lid switches) and pointer devices (needed for the mouse button
    /// virtual-key codes that `GetKeyState` supports on Windows).
    fn is_key_input_device(device: &Device) -> bool {
        if !device.supported_events().contains(EventType::KEY) {
            return false;
        }

        let Some(keys) = device.supported_keys() else {
            return false;
        };

        let is_keyboard = [
            KeyCode::KEY_A,
            KeyCode::KEY_Z,
            KeyCode::KEY_ENTER,
            KeyCode::KEY_SPACE,
        ]
        .into_iter()
        .all(|key| keys.contains(key));

        is_keyboard || keys.contains(KeyCode::BTN_LEFT)
    }

    /// ORs the pressed-key bitmap of every device into `buffer`, dropping devices whose
    /// state can no longer be read.
    fn poll_devices(devices: &mut Vec<Device>, buffer: &mut [u64; KEY_STATE_WORDS]) {
        devices.retain(|device| match device.get_key_state() {
            Ok(keys) => {
                for key in keys.iter() {
                    let code = key.code() as usize;
                    if code < KEY_STATE_BITS {
                        buffer[code / 64] |= 1 << (code % 64);
                    }
                }
                true
            }
            Err(err) => {
                log::debug!("dropping input device after key state read failure: {err}");
                false
            }
        });
    }
}

impl Keyboard for LinuxKeyboard {
    type KeyboardStateType = LinuxKeyboardState;

    /// Returns true wether the given key was pressed.
    /// This function accepts a valid microsoft virtual keycode.
    /// In case of supplying a invalid key this function will just return false cleanly.
    ///
    /// A list of all Keycodes can be found on the [msdn](https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes).
    fn is_down(&mut self, vk: i32) -> bool {
        self.state().map(|s| s.is_down(vk)).unwrap_or(false)
    }

    fn set_down(&mut self, _vk: i32, _down: bool) {
        // TODO: input injection would require uinput; matches the Windows stub.
    }

    /// Reads the entire keyboard state.
    fn state(&mut self) -> Result<Self::KeyboardStateType> {
        let mut devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());

        let mut buffer = [0u64; KEY_STATE_WORDS];
        Self::poll_devices(&mut devices, &mut buffer);

        if devices.is_empty() {
            *devices = Self::enumerate_devices();
            buffer = [0u64; KEY_STATE_WORDS];
            Self::poll_devices(&mut devices, &mut buffer);

            if devices.is_empty() {
                return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound).log_error(
                    "no readable keyboard devices in /dev/input (requires root or membership in the 'input' group)",
                ));
            }
        }

        Ok(LinuxKeyboardState { buffer })
    }
}

/// Represents the current Keyboardstate.
#[derive(Clone)]
pub struct LinuxKeyboardState {
    /// Bitset over evdev key codes `0..=KEY_MAX`.
    buffer: [u64; KEY_STATE_WORDS],
}

impl KeyboardState for LinuxKeyboardState {
    /// Returns true wether the given key was pressed.
    /// This function accepts a valid microsoft virtual keycode.
    /// In case of supplying a invalid key this function will just return false cleanly.
    ///
    /// A list of all Keycodes can be found on the [msdn](https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes).
    fn is_down(&self, vk: i32) -> bool {
        vk_to_keycodes(vk).iter().any(|&code| {
            let code = code as usize;
            code < KEY_STATE_BITS && self.buffer[code / 64] & (1 << (code % 64)) != 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_codes(codes: &[u16]) -> LinuxKeyboardState {
        let mut buffer = [0u64; KEY_STATE_WORDS];
        for &code in codes {
            let code = code as usize;
            buffer[code / 64] |= 1 << (code % 64);
        }
        LinuxKeyboardState { buffer }
    }

    #[test]
    fn state_translates_vks_to_evdev_bits() {
        let state = state_with_codes(&[30, 54, 0x116]); // KEY_A, KEY_RIGHTSHIFT, BTN_BACK

        assert!(state.is_down(0x41)); // 'A'
        assert!(state.is_down(0x10)); // VK_SHIFT via right shift
        assert!(state.is_down(0xA1)); // VK_RSHIFT
        assert!(state.is_down(0x05)); // VK_XBUTTON1 via BTN_BACK

        assert!(!state.is_down(0xA0)); // VK_LSHIFT not pressed
        assert!(!state.is_down(0x42)); // 'B' not pressed
        assert!(!state.is_down(0x07)); // unmapped VK
        assert!(!state.is_down(-1));
        assert!(!state.is_down(1000));
    }
}
