# idevice_pair

A tiny cross-platform GUI (egui/eframe) for working with iOS pairing files and developer settings—built on top of the [`idevice`](https://crates.io/crates/idevice) Rust crate.

It lets you:

* List USB-connected devices via `usbmuxd`
* Show key device info (Name, Model, iOS version, Build, UDID)
* Enable **Wireless Debugging** (`EnableWifiDebugging`)
* Check **Developer Mode** status
* Auto-mount the **Developer Disk Image** (iOS 17+)
* **Load** the current pairing record from `usbmuxd`
* **Generate** a fresh pairing file
* **Save** the pairing file to disk
* **Validate** the pairing file over LAN (TCP 62078), auto-discovering the device
* One-click **install** of the pairing file into supported apps via House Arrest/AFC

> Yes, the app is (mostly) a single Rust file. It’s fine. Please don't look at my desk. Send help.

---

## Download

Check the [releases](https://github.com/jkcoxson/idevice_pair/releases) page for the newest release.

## Features (details)

* **Device discovery (USB):** Filters to USB connections only. Uses `Lockdown` to pull values.
* **Device info panel:** Displays `DeviceName`, `ProductType`, `ProductVersion`, `BuildVersion`, `UniqueDeviceID`.
* **Wireless Debugging:** Toggles `com.apple.mobile.wireless_lockdown:EnableWifiDebugging = true`.
* **Developer Mode:** Reads `DeveloperModeStatus` from `com.apple.security.mac.amfi`.
* **DDI auto-mount (iOS 17+):** Attempts to mount the Developer Disk Image so dev tooling works out of the box.
* **Pairing file management:**

  * **Load** from `usbmuxd` (the one the host already has).
  * **Generate** a brand-new pairing (internally tweaks the BUID to avoid invalidating the currently used one).
  * **Save** to disk (`.plist`) and view the raw serialized plist in a monospace panel.
  * **Validate** over Wi-Fi (input IP or auto-discover; tests a Lockdown session on port 62078).
    
* **Install into apps:** If these are installed, writes the pairing file into their container:

  * `SideStore` → `ALTPairingFile.mobiledevicepairing`
  * `LiveContainer` → `SideStore/Documents/ALTPairingFile.mobiledevicepairing`
  * `Feather` → `pairingFile.plist`
  * `StikDebug` → `pairingFile.plist`
  * `Protokolle` → `pairingFile.plist`
  * `Antrag` → `pairingFile.plist`
    
* **Logs UI:** Built-in log window (toggle “logs” in the title row) using `egui_logger`.

---

## How it works (high level)

* **GUI thread:** `eframe`/`egui` renders the UI.
* **Worker runtime:** A multi-threaded `tokio` runtime handles device I/O.
* **Message passing:** Two unbounded channels connect GUI ⇄ worker:

  * `IdeviceCommands` → worker
  * `GuiCommands` → GUI
    
* **Network/services:** Talks to `usbmuxd`, `lockdownd`, `installation_proxy`, `afc/house_arrest`, and raw TCP (62078) for validation. A small discovery module maps Wi-Fi MAC ⇄ IP for LAN validation.

---

## Screenshots

*Add `icon.png` / screenshots here if you’d like.*
The app title is **“idevice pair”** and includes a log toggle.

---

## Requirements

* **Rust**: stable toolchain (`cargo`).
* **usbmuxd / Apple Mobile Device**:

  * **macOS**: Built-in (`usbmuxd` runs by default).
  * **Windows**: Install **Apple’s iTunes from apple.com** (not the Microsoft Store version) and make sure Apple Mobile Device Service is running.
  * **Linux**: Install `usbmuxd` and start the service; add proper **udev rules** so the device is accessible without root.
* **iOS device** + trust the computer.
* 
## Download usbmxd

**Linux**:

```console
sudo apt install usbmuxd
sudo systemctl enable --now usbmuxd
```

**Windows**: Download [Itunes](https://www.apple.com/itunes/download/win64/)

## Build & Run

```bash
# in the repo root
cargo run --release
```

* On **Windows release builds**, the console window is hidden by:

  ```rust
  #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
  ```
* The app embeds `icon.png` from the project root.

---

## Usage

1. **Connect your device via USB.**
   Launch the app; your devices load automatically. Click **Refresh…** if needed.

2. **Select a device.**
   The app will:

   * Enable Wireless Debugging (or show errors)
   * Check Developer Mode
   * Attempt to mount the DDI (iOS 17+)
   * Populate device info
   * Detect supported apps for install targets

3. **Pairing file:**

   * **Load**: Pull from `usbmuxd`’s current host pairing.
   * **Generate**: Create a new pairing file (useful for alternate hosts or apps).
   * **Save to File**: Writes a `.plist` you can copy around.

4. **Validate over LAN (optional):**
   Enter IP or leave blank for auto-discover. The app tries a Lockdown session to confirm the file works over Wi-Fi.

5. **Install into apps (optional):**
   If a supported app is installed, press **Install** to drop the pairing file into its container path via House Arrest/AFC.

6. **Logs:**
   Click the **logs** toggle in the header; you can adjust categories in the panel.

---

## Troubleshooting

* **“Failed to connect to usbmuxd”**

  * **Windows:** Ensure you installed **iTunes from Apple’s website**, not the Store version, and that **Apple Mobile Device Service** is running.
  * **Linux:** Install and start `usbmuxd`; confirm user permissions/udev rules.
  * **macOS:** `usbmuxd` should be present; if it fails consistently, file an issue with logs.

* **Developer Mode shows “Disabled”**

  * Enable Developer Mode on the device (Settings → Privacy & Security → Developer Mode). Reboot if prompted.

* **DDI mount fails**

  * Ensure developer mode is enabled.

* **Validation fails over LAN**

  * Confirm the device and host are on the same subnet and the device’s **Wireless Debugging** is enabled.
  * If you typed an IP, double-check it; leaving it blank lets the app auto-discover.

* **Install into app fails**

  * Make sure the target app is actually installed.

---

## Security & Notes

* Pairing files grant trusted access to your device over USB/Wi-Fi. **Treat them like credentials**—don’t share them publicly and remove them from untrusted hosts.
* “Generate” uses a new HostID/BUID (with a small tweak to avoid invalidating a currently active host), so existing sessions on your main machine should remain usable.

---

## Development

Key crates you’ll see in `Cargo.toml`:

* `eframe`, `egui`, `egui_logger`
* `tokio` (multi-thread runtime), `log`
* `rfd` (native file dialogs)
* `idevice` (Lockdown, Installation Proxy, House Arrest/AFC, usbmuxd, etc.)

Build with ``cargo``

```sh
cargo build --release
```

Project layout (intentionally(?) minimal):

```
src/
  main.rs        # the whole app (UI + command enums + runtime wiring)
  discover.rs    # LAN discovery (maps Wi-Fi MAC -> IP)
  mount.rs       # DDI auto-mount helpers
icon.png
```

Messaging:

```rust
// GUI -> worker
enum IdeviceCommands { /* ... */ }

// worker -> GUI
enum GuiCommands { /* ... */ }
```

---

## Roadmap / Ideas

* Head empty, no ideas

---

## License

MIT

---

## Disclaimer

This project interfaces with Apple services (`lockdownd`, `usbmuxd`, etc.). It’s intended for legitimate development and device management workflows. You are responsible for complying with Apple’s terms and local laws.

ChatGPT wrote most of this readme. I'm so sorry.
