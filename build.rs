// Jackson Coxson

use reqwest::blocking::get;
use std::fs;
use std::path::Path;

const URLS: [&str; 3] = [
    "https://github.com/doronz88/DeveloperDiskImage/raw/refs/heads/main/PersonalizedImages/Xcode_iOS_DDI_Personalized/BuildManifest.plist",
    "https://github.com/doronz88/DeveloperDiskImage/raw/refs/heads/main/PersonalizedImages/Xcode_iOS_DDI_Personalized/Image.dmg",
    "https://github.com/doronz88/DeveloperDiskImage/raw/refs/heads/main/PersonalizedImages/Xcode_iOS_DDI_Personalized/Image.dmg.trustcache",
];
const OUTPUT_DIR: &str = "DDI";
const OUTPUT_FILES: [&str; 3] = [
    "DDI/BuildManifest.plist",
    "DDI/Image.dmg",
    "DDI/Image.dmg.trustcache",
];

fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        res.compile().unwrap();
    }

    println!("cargo:rerun-if-changed=build.rs");
    for file in OUTPUT_FILES {
        println!("cargo:rerun-if-changed={file}");
    }

    // Ensure output directory exists
    if !Path::new(OUTPUT_DIR).exists() {
        fs::create_dir_all(OUTPUT_DIR).expect("Failed to create DDI directory");
    }

    for (url, output_file) in URLS.iter().zip(OUTPUT_FILES.iter()) {
        if file_exists_with_content(output_file) {
            continue;
        }

        println!("Downloading {output_file}...");
        let response = get(*url).expect("Failed to send request");
        let bytes = response.bytes().expect("Failed to read response");
        fs::write(output_file, &bytes).expect("Failed to write file");
    }
}

fn file_exists_with_content(path: &str) -> bool {
    fs::metadata(path).map(|metadata| metadata.len() > 0).unwrap_or(false)
}
