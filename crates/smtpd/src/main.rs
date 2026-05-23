use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("rMail SMTPD (scaffold) starting");
    println!("shared: {}", rmail_common::hello());
    Ok(())
}
