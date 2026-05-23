use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("rMail IMAPD (scaffold) starting");
    println!("shared: {}", rmail_common::hello());
    Ok(())
}
