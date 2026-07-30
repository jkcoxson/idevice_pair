use reqwest::blocking::get;
use std::fs;

const ARTIFACTS: [(&str, &str); 3] = [
    (
        "https://github.com/doronz88/DeveloperDiskImage/raw/refs/heads/main/PersonalizedImages/Xcode_iOS_DDI_Personalized/BuildManifest.plist",
        "DDI/BuildManifest.plist",
    ),
    (
        "https://github.com/doronz88/DeveloperDiskImage/raw/refs/heads/main/PersonalizedImages/Xcode_iOS_DDI_Personalized/Image.dmg",
        "DDI/Image.dmg",
    ),
    (
        "https://github.com/doronz88/DeveloperDiskImage/raw/refs/heads/main/PersonalizedImages/Xcode_iOS_DDI_Personalized/Image.dmg.trustcache",
        "DDI/Image.dmg.trustcache",
    ),
];

fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("icon.ico");
        res.compile().unwrap();
    }

    for (_, file) in ARTIFACTS {
        println!("cargo:rerun-if-changed={file}");
    }

    fs::create_dir_all("DDI").expect("Failed to create DDI directory");

    for (url, output_file) in ARTIFACTS {
        if fs::metadata(output_file).is_ok_and(|metadata| metadata.len() > 0) {
            continue;
        }

        println!("Downloading {output_file}...");
        let response = get(url).expect("Failed to send request");
        let bytes = response.bytes().expect("Failed to read response");
        fs::write(output_file, &bytes).expect("Failed to write file");
    }
}
