# iDevice Pair

A cross-platform GUI application for managing iOS device pairing and wireless debugging. This tool provides an easy-to-use interface for enabling wireless debugging, managing pairing files, and working with various iOS sideloading applications.

## Features

- **Device Management**: Automatically discover and connect to iOS devices via USB
- **Wireless Debugging**: Enable wireless debugging on iOS devices
- **Developer Mode**: Check and monitor developer mode status
- **Pairing Files**: Generate, load, and validate device pairing files
- **App Integration**: Support for popular sideloading apps including:
  - SideStore
  - LiveContainer
  - Feather
  - StikDebug
  - Protokolle
  - Antrag
- **Network Discovery**: Discover devices on the local network
- **Developer Disk Image Mounting**: Automatically mount required developer images

## Prerequisites

- **macOS/Linux/Windows**: Cross-platform support
- **iOS Device**: Connected via USB or on the same network
- **Developer Mode**: Must be enabled on the iOS device for full functionality
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
3. **Select your device** from the dropdown menu
4. **Enable wireless debugging** if desired for wireless connectivity

### Managing Pairing Files

The application can generate and manage pairing files for various sideloading applications:

1. **Load existing pairing file**: Click "Load Pairing File" to import from your device
2. **Generate new pairing file**: Click "Generate Pairing File" to create a fresh pairing
3. **Save pairing file**: Export the pairing file for use with supported applications
4. **Validate pairing**: Test the pairing file against a network-connected device

## Pairing Guide

idevice_pair allows you to create a pairing file for programs like StikDebug to communicate with your device remotely. This pairing file is device-specific and required for tools like StikDebug to function correctly.

### Prerequisites for Pairing

Before creating a pairing file, ensure you have:

1. **Set a passcode** on your iOS device
2. **Sideloaded an app** with the get-task-allow entitlement (can be done with [SideStore](https://sidestore.io/) or similar tools)
3. **Enabled Developer Mode** on your iOS/iPadOS device (found in Settings → Privacy & Security after sideloading an app)

### Installation Instructions

#### macOS
1. Download [idevice pair for macOS](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--macos-universal.dmg)
2. Open the Disk Image and drag `idevice pair` to `Applications`

#### Windows
1. Install iTunes ([64-bit](https://apple.com/itunes/download/win64) or [32-bit](https://apple.com/itunes/download/win32)) from Apple's website
2. Download [idevice pair for Windows](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--windows-x86_64.exe) and save it to a memorable location

#### Linux
1. Install usbmuxd: 
   ```bash
   sudo apt install -y usbmuxd
   ```
2. Download idevice_pair for your architecture:
   - [x86_64](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--linux-x86_64.AppImage)
   - [AArch64](https://github.com/jkcoxson/idevice_pair/releases/latest/download/idevice_pair--linux-aarch64.AppImage)
3. Make the downloaded file executable

### Pairing Instructions

1. **Connect your device** to your computer via USB cable
   - If prompted, select `Trust` and enter your passcode
2. **Open idevice pair** and select your device from the dropdown menu
3. **Load pairing file**: 
   - Ensure your device is unlocked and on the home screen
   - Click `Load Pairing File`
   - If prompted on your device, tap `Trust` and enter your passcode
4. **Install for your app**:
   - Keep your device unlocked and on the home screen
   - Scroll down and click `Install` under your target application (e.g., "StikDebug")
   - You should see `Success` appear in green

## Supported Applications

The tool includes built-in support for pairing file formats used by:

- **SideStore**: `ALTPairingFile.mobiledevicepairing`
- **LiveContainer**: `SideStore/Documents/ALTPairingFile.mobiledevicepairing`
- **Feather**: `pairingFile.plist`
- **StikDebug**: `pairingFile.plist`
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

### Wireless Connection Issues
- Verify both devices are on the same network
- Ensure wireless debugging is enabled on the iOS device
- Check firewall settings that might block port 62078

### Pairing File Issues
- Make sure developer mode is enabled on your iOS device
- Verify the pairing file format matches your target application
- Try generating a fresh pairing file if validation fails

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is licensed under the MIT License.

## Acknowledgments

- Built with the [idevice](https://crates.io/crates/idevice) library for iOS device communication
- GUI powered by [egui](https://github.com/emilk/egui)
