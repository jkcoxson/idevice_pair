use std::path::Path;

use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_app_kit::{NSSharingServicePicker, NSView};
use objc2_foundation::{NSArray, NSRectEdge, NSString, NSURL};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

pub fn share_file(
    frame: &eframe::Frame,
    path: &Path,
) -> Result<Retained<NSSharingServicePicker>, String> {
    let handle = frame
        .window_handle()
        .map_err(|e| format!("no window handle: {e}"))?;
    let RawWindowHandle::AppKit(appkit) = handle.as_raw() else {
        return Err("not running under AppKit".to_string());
    };

    let ns_view: Retained<NSView> = unsafe {
        Retained::retain(appkit.ns_view.as_ptr().cast())
            .ok_or_else(|| "null NSView".to_string())?
    };

    let path_str = path
        .to_str()
        .ok_or_else(|| "pairing file path is not valid UTF-8".to_string())?;
    let ns_path = NSString::from_str(path_str);
    let file_url = NSURL::fileURLWithPath(&ns_path);

    let items = NSArray::from_retained_slice(&[Retained::<objc2::runtime::AnyObject>::from(file_url)]);
    let picker = unsafe { NSSharingServicePicker::initWithItems(NSSharingServicePicker::alloc(), &items) };

    let bounds = ns_view.bounds();
    picker.showRelativeToRect_ofView_preferredEdge(bounds, &ns_view, NSRectEdge::MinY);

    Ok(picker)
}
