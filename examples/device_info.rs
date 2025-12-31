use rswidevine::device::Device;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .expect("Usage: device_info <device.wvd>");

    let device = Device::from_path(path)?;
    println!("device_type: {:?}", device.device_type);
    println!("system_id: {}", device.system_id);
    println!("security_level: {}", device.security_level);
    println!("has_vmp: {}", device.vmp.is_some());

    Ok(())
}
