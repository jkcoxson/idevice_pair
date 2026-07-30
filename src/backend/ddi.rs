use idevice::{IdeviceError, mobile_image_mounter::ImageMounter};

use super::link::Link;

const BUILD_MANIFEST: &[u8] = include_bytes!("../../DDI/BuildManifest.plist");
const IMAGE: &[u8] = include_bytes!("../../DDI/Image.dmg");
const TRUST_CACHE: &[u8] = include_bytes!("../../DDI/Image.dmg.trustcache");

pub async fn mounted(link: &mut Link) -> Result<bool, IdeviceError> {
    let mut mounter = link.service::<ImageMounter>().await?;
    Ok(!mounter.copy_devices().await?.is_empty())
}

pub async fn mount(link: &mut Link) -> Result<(), IdeviceError> {
    let mut mounter = link.service::<ImageMounter>().await?;
    let unique_chip_id = link.unique_chip_id().await?;
    match link {
        Link::Usbmuxd { provider, .. } => {
            mounter
                .mount_personalized(
                    provider,
                    IMAGE.to_vec(),
                    TRUST_CACHE.to_vec(),
                    BUILD_MANIFEST,
                    None,
                    unique_chip_id,
                )
                .await?;
        }
        Link::Rsd { handle, rsd, .. } => {
            mounter
                .mount_personalized_rsd(
                    handle,
                    rsd,
                    IMAGE.to_vec(),
                    TRUST_CACHE.to_vec(),
                    BUILD_MANIFEST,
                    None,
                    unique_chip_id,
                )
                .await?;
        }
    }

    Ok(())
}
