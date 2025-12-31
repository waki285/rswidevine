use rswidevine::pssh::Pssh;

fn main() -> anyhow::Result<()> {
    let input = std::env::args()
        .nth(1)
        .expect("Usage: pssh_inspect <pssh_base64>");

    let pssh = Pssh::from_base64(&input)?;
    println!("version: {}", pssh.version);
    println!("flags: {}", pssh.flags);
    println!("system_id: {}", pssh.system_id);

    let key_ids = pssh.key_ids()?;
    if key_ids.is_empty() {
        println!("key_ids: <none>");
    } else {
        for kid in key_ids {
            println!("kid: {}", kid);
        }
    }

    Ok(())
}
