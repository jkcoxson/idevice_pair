# idevice_pair

A cross-platform GUI for creating iOS pairing files, over USB or over Wi-Fi.

## Features

- **Devices over USB and Wi-Fi**: usbmuxd devices show up automatically, and Apple TV
  or a device running iOS 27 or later can pair over the network with no cable
- **Pairing files**: create a lockdown or a remote pairing (RPPairing) file on either transport
- **Two destinations**: save the file to disk, or write it straight into an app's
  Documents directory over AFC
- **Validation**: check that a file you just created actually works
- **Device state**: developer mode, developer disk image mounting, and wireless
  debugging (enabled over USB so the device can be reached over Wi-Fi later)

Apps with a known pairing file location:

- [SideStore](https://github.com/SideStore/SideStore)
- [LiveContainer+SideStore](https://github.com/LiveContainer/LiveContainer)
- [StikDebug](https://github.com/StephenDev0/StikDebug)
- [SparseBox](https://github.com/spadaria/SparseBox)
- [Feather](https://github.com/khcrysalis/Feather)
- [Protokolle](https://github.com/khcrysalis/Protokolle)
- [Antrag](https://github.com/khcrysalis/Antrag)
- [KSign](https://github.com/Nyasami/Ksign)
- [EnsWilde](https://github.com/YangJiiii/EnsWilde)
- [Reynard Browser](https://github.com/minh-ton/reynard-browser)
- [Auto Capture](https://apps.apple.com/us/app/dev-auto-capture/id6755616902)
- [StosDebug](https://github.com/stossy11/StosDebug)
- [StikStore](https://stikstore.app/)

## Prerequisites

- **macOS/Linux/Windows**, with usbmuxd installed for USB devices
- **An iOS/iPadOS device** with a passcode set
- **Rust**, to build from source

## Installation

### macOS
1. Download [idevice_pair for macOS](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--macos-universal.dmg)
2. Open the disk image and drag `idevice_pair` to `Applications`

### Windows
1. Install [iTunes](https://apple.com/itunes/download/win64)
2. Download [idevice_pair for Windows](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--windows-x86_64.exe)

### Linux
1. Install usbmuxd:
   ```bash
   sudo apt install -y usbmuxd
   ```
2. Download the AppImage for your architecture and make it executable:
   - [x86_64](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--linux-x86_64.AppImage)
   - [AArch64](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--linux-aarch64.AppImage)

### From source
```bash
git clone https://github.com/jkcoxson/idevice_pair.git
cd idevice_pair
cargo run --release
```

## Usage

### Over USB

1. Connect the device and tap `Trust` if asked
2. Pick it from the device dropdown
3. Choose `Lockdown` or `Remote pairing`, then click `Load` or `Create`
   - Remote pairing needs iOS 17.4 or later; lockdown works everywhere
   - Lockdown reuses the record usbmuxd already holds, and only pairs if there isn't one
   - Keep the device unlocked on the home screen while pairing
4. Click `Save to file…`, or click an app's name to write the file into it

A device usbmuxd sees over Wi-Fi is already paired, so it appears in the dropdown too
and works the same as a cabled one, without the cable.

### Over Wi-Fi with iPhone or iPad

Requires iOS 27 or later, with both the device and computer on the same network.

1. Click `Pair over Wi-Fi`
2. Pick this computer on your device
3. Type the code shown by idevice_pair into your device
4. The device joins the dropdown for as long as the app is open

The remote pairing is only kept in memory, so pair again after a restart. The
RPPairing record created by Wi-Fi onboarding is loaded automatically on the device
page. Lockdown pairing is unavailable for this transport; connect through usbmuxd
to obtain a lockdown pairing file.

### Over Wi-Fi with Apple TV

1. Put the Apple TV into manual remote pairing mode by choosing Settings > Remotes and Devices > Remote App and Devices.
2. Select the Apple TV from the device dropdown
3. Enter the code shown on the Apple TV
4. The Apple TV remains in the dropdown as a paired device for as long as the app is open

## Troubleshooting

### Device not detected
- Check the device is connected and trusted, or reconnect it
- On Linux, make sure the usbmuxd service is running

### Wireless pairing doesn't show this computer
- Both sides must be on the same network, with mDNS not blocked
- Only iOS 27 and later can start pairing from the device
- For Apple TV, make sure manual pairing mode is open before starting

### Pairing file doesn't work in an app
- Check the app expects the kind of file you created
- Create a fresh one and use `Validate` to confirm it works

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

MIT
