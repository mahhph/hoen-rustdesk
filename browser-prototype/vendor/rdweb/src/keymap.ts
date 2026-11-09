// Physical key tables, keyed by KeyboardEvent.code.
//
// Map mode sends the key's code in the *peer's* platform format:
//   win   - PC/AT set 1 scan code, 0xE0xx for extended keys
//   linux - X11 keycode (evdev code + 8)
//   mac   - macOS virtual key code (kVK_*)
// Legacy mode uses `ctl` (ControlKey) for keys that do not produce text.

import { ControlKey } from "./proto/session_pb.js";

export interface KeyCodes {
  win?: number;
  /** evdev code; the X11 keycode sent on the wire is this + 8. */
  evdev?: number;
  mac?: number;
  ctl?: ControlKey;
}

const K = (win: number | undefined, evdev: number | undefined, mac: number | undefined, ctl?: ControlKey): KeyCodes => ({
  win,
  evdev,
  mac,
  ctl,
});

export const KEYMAP: Record<string, KeyCodes> = {
  KeyA: K(0x1e, 30, 0x00),
  KeyB: K(0x30, 48, 0x0b),
  KeyC: K(0x2e, 46, 0x08),
  KeyD: K(0x20, 32, 0x02),
  KeyE: K(0x12, 18, 0x0e),
  KeyF: K(0x21, 33, 0x03),
  KeyG: K(0x22, 34, 0x05),
  KeyH: K(0x23, 35, 0x04),
  KeyI: K(0x17, 23, 0x22),
  KeyJ: K(0x24, 36, 0x26),
  KeyK: K(0x25, 37, 0x28),
  KeyL: K(0x26, 38, 0x25),
  KeyM: K(0x32, 50, 0x2e),
  KeyN: K(0x31, 49, 0x2d),
  KeyO: K(0x18, 24, 0x1f),
  KeyP: K(0x19, 25, 0x23),
  KeyQ: K(0x10, 16, 0x0c),
  KeyR: K(0x13, 19, 0x0f),
  KeyS: K(0x1f, 31, 0x01),
  KeyT: K(0x14, 20, 0x11),
  KeyU: K(0x16, 22, 0x20),
  KeyV: K(0x2f, 47, 0x09),
  KeyW: K(0x11, 17, 0x0d),
  KeyX: K(0x2d, 45, 0x07),
  KeyY: K(0x15, 21, 0x10),
  KeyZ: K(0x2c, 44, 0x06),

  Digit1: K(0x02, 2, 0x12),
  Digit2: K(0x03, 3, 0x13),
  Digit3: K(0x04, 4, 0x14),
  Digit4: K(0x05, 5, 0x15),
  Digit5: K(0x06, 6, 0x17),
  Digit6: K(0x07, 7, 0x16),
  Digit7: K(0x08, 8, 0x1a),
  Digit8: K(0x09, 9, 0x1c),
  Digit9: K(0x0a, 10, 0x19),
  Digit0: K(0x0b, 11, 0x1d),

  Minus: K(0x0c, 12, 0x1b),
  Equal: K(0x0d, 13, 0x18),
  BracketLeft: K(0x1a, 26, 0x21),
  BracketRight: K(0x1b, 27, 0x1e),
  Backslash: K(0x2b, 43, 0x2a),
  Semicolon: K(0x27, 39, 0x29),
  Quote: K(0x28, 40, 0x27),
  Backquote: K(0x29, 41, 0x32),
  Comma: K(0x33, 51, 0x2b),
  Period: K(0x34, 52, 0x2f),
  Slash: K(0x35, 53, 0x2c),
  IntlBackslash: K(0x56, 86, 0x0a),
  IntlRo: K(0x73, 89, 0x5e),
  IntlYen: K(0x7d, 124, 0x5d),

  Escape: K(0x01, 1, 0x35, ControlKey.Escape),
  Enter: K(0x1c, 28, 0x24, ControlKey.Return),
  Backspace: K(0x0e, 14, 0x33, ControlKey.Backspace),
  Tab: K(0x0f, 15, 0x30, ControlKey.Tab),
  Space: K(0x39, 57, 0x31, ControlKey.Space),
  CapsLock: K(0x3a, 58, 0x39, ControlKey.CapsLock),
  ShiftLeft: K(0x2a, 42, 0x38, ControlKey.Shift),
  ShiftRight: K(0x36, 54, 0x3c, ControlKey.RShift),
  ControlLeft: K(0x1d, 29, 0x3b, ControlKey.Control),
  ControlRight: K(0xe01d, 97, 0x3e, ControlKey.RControl),
  AltLeft: K(0x38, 56, 0x3a, ControlKey.Alt),
  AltRight: K(0xe038, 100, 0x3d, ControlKey.RAlt),
  MetaLeft: K(0xe05b, 125, 0x37, ControlKey.Meta),
  MetaRight: K(0xe05c, 126, 0x36, ControlKey.RWin),
  ContextMenu: K(0xe05d, 127, 0x6e, ControlKey.Apps),

  F1: K(0x3b, 59, 0x7a, ControlKey.F1),
  F2: K(0x3c, 60, 0x78, ControlKey.F2),
  F3: K(0x3d, 61, 0x63, ControlKey.F3),
  F4: K(0x3e, 62, 0x76, ControlKey.F4),
  F5: K(0x3f, 63, 0x60, ControlKey.F5),
  F6: K(0x40, 64, 0x61, ControlKey.F6),
  F7: K(0x41, 65, 0x62, ControlKey.F7),
  F8: K(0x42, 66, 0x64, ControlKey.F8),
  F9: K(0x43, 67, 0x65, ControlKey.F9),
  F10: K(0x44, 68, 0x6d, ControlKey.F10),
  F11: K(0x57, 87, 0x67, ControlKey.F11),
  F12: K(0x58, 88, 0x6f, ControlKey.F12),
  F13: K(0x64, 183, 0x69),
  F14: K(0x65, 184, 0x6b),
  F15: K(0x66, 185, 0x71),
  F16: K(0x67, 186, 0x6a),
  F17: K(0x68, 187, 0x40),
  F18: K(0x69, 188, 0x4f),
  F19: K(0x6a, 189, 0x50),
  F20: K(0x6b, 190, 0x5a),

  PrintScreen: K(0xe037, 99, undefined, ControlKey.Snapshot),
  ScrollLock: K(0x46, 70, undefined, ControlKey.Scroll),
  Pause: K(undefined, 119, undefined, ControlKey.Pause),
  Insert: K(0xe052, 110, 0x72, ControlKey.Insert),
  Home: K(0xe047, 102, 0x73, ControlKey.Home),
  PageUp: K(0xe049, 104, 0x74, ControlKey.PageUp),
  Delete: K(0xe053, 111, 0x75, ControlKey.Delete),
  End: K(0xe04f, 107, 0x77, ControlKey.End),
  PageDown: K(0xe051, 109, 0x79, ControlKey.PageDown),
  ArrowRight: K(0xe04d, 106, 0x7c, ControlKey.RightArrow),
  ArrowLeft: K(0xe04b, 105, 0x7b, ControlKey.LeftArrow),
  ArrowDown: K(0xe050, 108, 0x7d, ControlKey.DownArrow),
  ArrowUp: K(0xe048, 103, 0x7e, ControlKey.UpArrow),

  NumLock: K(0x45, 69, 0x47, ControlKey.NumLock),
  NumpadDivide: K(0xe035, 98, 0x4b, ControlKey.Divide),
  NumpadMultiply: K(0x37, 55, 0x43, ControlKey.Multiply),
  NumpadSubtract: K(0x4a, 74, 0x4e, ControlKey.Subtract),
  NumpadAdd: K(0x4e, 78, 0x45, ControlKey.Add),
  NumpadEnter: K(0xe01c, 96, 0x4c, ControlKey.NumpadEnter),
  NumpadDecimal: K(0x53, 83, 0x41, ControlKey.Decimal),
  NumpadEqual: K(0x59, 117, 0x51, ControlKey.Equals),
  NumpadComma: K(0x7e, 121, 0x5f),
  Numpad0: K(0x52, 82, 0x52, ControlKey.Numpad0),
  Numpad1: K(0x4f, 79, 0x53, ControlKey.Numpad1),
  Numpad2: K(0x50, 80, 0x54, ControlKey.Numpad2),
  Numpad3: K(0x51, 81, 0x55, ControlKey.Numpad3),
  Numpad4: K(0x4b, 75, 0x56, ControlKey.Numpad4),
  Numpad5: K(0x4c, 76, 0x57, ControlKey.Numpad5),
  Numpad6: K(0x4d, 77, 0x58, ControlKey.Numpad6),
  Numpad7: K(0x47, 71, 0x59, ControlKey.Numpad7),
  Numpad8: K(0x48, 72, 0x5b, ControlKey.Numpad8),
  Numpad9: K(0x49, 73, 0x5c, ControlKey.Numpad9),

  AudioVolumeMute: K(0xe020, 113, 0x4a, ControlKey.VolumeMute),
  AudioVolumeDown: K(0xe02e, 114, 0x49, ControlKey.VolumeDown),
  AudioVolumeUp: K(0xe030, 115, 0x48, ControlKey.VolumeUp),
  KanaMode: K(0x70, 93, 0x68, ControlKey.Kana),
  Convert: K(0x79, 92, undefined, ControlKey.Convert),
  NonConvert: K(0x7b, 94, undefined),
  Lang1: K(0x72, 122, 0x68, ControlKey.Hangul),
  Lang2: K(0x71, 123, 0x66, ControlKey.Hanja),
};

export type PeerOs = "windows" | "linux" | "macos" | "android" | "ios" | "unknown";

export function peerOsFromPlatform(platform: string): PeerOs {
  const p = platform.toLowerCase();
  if (p.startsWith("win")) return "windows";
  if (p.startsWith("mac") || p === "darwin") return "macos";
  if (p.startsWith("linux")) return "linux";
  if (p.startsWith("android")) return "android";
  if (p.startsWith("ios")) return "ios";
  return "unknown";
}

/** The Map-mode code for `code` on a peer running `os`, if there is one. */
export function mapCode(code: string, os: PeerOs): number | undefined {
  const k = KEYMAP[code];
  if (!k) return undefined;
  switch (os) {
    case "windows":
      return k.win;
    case "macos":
      return k.mac;
    case "linux":
      return k.evdev === undefined ? undefined : k.evdev + 8;
    default:
      return undefined;
  }
}

export function isModifierCode(code: string): boolean {
  return /^(Shift|Control|Alt|Meta)(Left|Right)$/.test(code);
}
