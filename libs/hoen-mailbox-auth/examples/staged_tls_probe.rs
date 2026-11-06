use hoen_mailbox_auth::mailbox::{AccessToken,Fingerprint,MailboxClient};
fn main() -> Result<(),Box<dyn std::error::Error>> {
 let pem=std::fs::read(std::env::args().nth(1).ok_or("public certificate path required")?)?;
 let pin=*Fingerprint::parse("7fe74d2d232d6ae1a3f3efd0a453a82655f5a52c3c103ed113341853b839995f")?.as_bytes();
 let token=|| AccessToken::from_encoded(&"A".repeat(43));
 let good=MailboxClient::new_pinned("https://127.0.0.1:42832",&pem,token()?,pin)?;
 assert!(good.list()?.is_empty());
 let bad=MailboxClient::new_pinned("https://127.0.0.1:42832",&pem,token()?,[0;32])?;
 assert!(bad.list().is_err());
 println!("PASS: native sole-root/SAN/exact-pin connection; wrong-pin rejected. Synthetic credential only.");
 Ok(())
}
