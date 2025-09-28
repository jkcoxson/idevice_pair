# idevice_pair

A cross-platform GUI application for managing iOS device pairing and wireless debugging. This tool provides an easy-to-use interface for managing pairing files which work with various iOS applications.

## Features

- **Device Management**: Automatically discover and connect to iOS devices via USB
- **Developer Mode**: Monitor developer mode status
- **Pairing Files**: Generate, load, and validate device pairing files
- **App Integration**: Support for popular apps including:
  - SideStore
  - LiveContainer+SideStore
  - StikDebug
  - Feather
  - Protokolle
  - Antrag
- **Network Discovery**: Validate pairings for devices on the local network
- **Developer Disk Image Mounting**: Automatically mount required developer images

## Prerequisites

- **macOS/Linux/Windows**: Cross-platform support, must have usbmuxd installed
- **iOS/iPadOS Device**: Must have a passcode set and be connected via USB
- **Rust**: Required for building from source

## Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/jkcoxson/idevice_pair.git
   cd idevice_pair
   ```

2. Build the application:
   ```bash
   cargo build --release
   ```

3. Run the application:
   ```bash
   cargo run --release
   ```

## Usage

### Getting Started

1. **Connect your iOS device** via USB to your computer
2. **Launch the application** - it will automatically scan for connected devices
3. **Select your device** from the dropdown menu if not already selected

### Managing Pairing Files

The application can generate and manage pairing files for various applications:

1. **Load existing pairing file**: Click `Load` to import from your computer (recommended)
2. **Generate new pairing file**: Click `Generate` to create a fresh pairing
3. **Save pairing file**: Export the pairing file to your computer or your supported applications
4. **Validate pairing**: Test the pairing file against a local network-connected device

## Pairing Guide

### Prerequisites for Pairing

Before creating a pairing file, ensure you have:

1. **Set a passcode** on your iOS device

(For maximum performance, you should also)

2. **Sideload an app** (can be done with [SideStore](https://sidestore.io/) or a certificate + signer)

3. **Enable Developer Mode** on your iOS/iPadOS device (found in Settings → Privacy & Security after sideloading an app)

### Installation Instructions

#### macOS
1. Download [idevice_pair for macOS](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--macos-universal.dmg)
2. Open the Disk Image and drag `idevice_pair` to `Applications`

#### Windows
1. Install [iTunes](https://apple.com/itunes/download/win64) from Apple's website
2. Download [idevice_pair for Windows](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--windows-x86_64.exe) and save it to a memorable location

#### Linux
1. Install usbmuxd: 
   ```bash
   sudo apt install -y usbmuxd
   ```
2. Download idevice_pair for your architecture and save it to a memorable location:
   - [x86_64](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--linux-x86_64.AppImage)
   - [AArch64](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--linux-aarch64.AppImage)
3. Make the downloaded file executable

### Pairing Instructions

1. **Connect your device** to your computer via USB cable
   - If prompted, select `Trust` and enter your passcode
2. **Open idevice_pair** and select your device from the dropdown menu
3. **Load pairing file**: 
   - Ensure your device is unlocked and on the home screen
   - Click `Load`
   - If prompted on your device, tap `Trust` and enter your passcode
4. **Install for your app**:
   - Keep your device unlocked and on the home screen
   - Scroll down and click `Install` under your target application (e.g., "StikDebug")
   - You should see `Success` appear in green

## Supported Applications

The tool includes built-in support for pairing file formats used by:

- **SideStore**: `ALTPairingFile.mobiledevicepairing`
- **LiveContainer+SideStore**: `SideStore/Documents/ALTPairingFile.mobiledevicepairing`
- **StikDebug**: `pairingFile.plist`
- **Feather**: `pairingFile.plist`
- **Protokolle**: `pairingFile.plist`
- **Antrag**: `pairingFile.plist`

## Dependencies

This project uses several key dependencies:

- **[idevice](https://crates.io/crates/idevice)**: Core iOS device communication library
- **[egui](https://crates.io/crates/egui)**: Immediate mode GUI framework
- **[eframe](https://crates.io/crates/eframe)**: Application framework for egui
- **[tokio](https://crates.io/crates/tokio)**: Asynchronous runtime
- **[rfd](https://crates.io/crates/rfd)**: Native file dialogs

For a complete list of dependencies, see [`Cargo.toml`](Cargo.toml).

## Troubleshooting

### Device Not Detected
- Ensure your iOS device is connected via USB
- Check that the device is trusted on your computer
- Try disconnecting and reconnecting the device

### Pairing File Issues
- Ensure developer mode is enabled on your iOS device
- Verify the pairing file format matches your target application (.plist or .mobiledevicepairing)
- Try creating a fresh pairing file using the `load` button if it doesn't function as expected
  
### Wireless Connection Issues
- Verify both devices are on the same network
- Check firewall settings that might block port 62078

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is licensed under the MIT License.

## Acknowledgments

- Built with the [idevice](https://crates.io/crates/idevice) library for iOS device communication
- GUI powered by [egui](https://github.com/emilk/egui)
