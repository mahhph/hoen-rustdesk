//! All blocking HTTPS client construction, requests and destruction stay on one worker.
use hbb_common::tokio::sync::{mpsc, oneshot};
use hoen_mailbox_auth::mailbox::{
    AccessToken, ConsumedGrant, Error, GrantToken, Identity, IssuedGrant, Machine, MailboxClient,
    Registration,
};

enum Request {
    Register(Registration, oneshot::Sender<Result<Machine, Error>>),
    Lookup(Identity, oneshot::Sender<Result<Machine, Error>>),
    List(oneshot::Sender<Result<Vec<Machine>, Error>>),
    Issue(
        Identity,
        [u8; 32],
        oneshot::Sender<Result<IssuedGrant, Error>>,
    ),
    Consume(
        Identity,
        GrantToken,
        [u8; 32],
        oneshot::Sender<Result<ConsumedGrant, Error>>,
    ),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[hbb_common::tokio::test]
    async fn pinned_client_rejects_invalid_trust_before_requests() {
        let token = AccessToken::from_encoded("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(matches!(MailboxWorker::start_with_pin("https://localhost/".into(), Vec::new(), token, Some([7;32])).await, Err(Error::InvalidConfiguration)));
    }

    #[hbb_common::tokio::test]
    async fn invalid_trust_configuration_fails_cleanly_from_async_runtime() {
        let token =
            AccessToken::from_encoded("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(matches!(
            MailboxWorker::start("http://127.0.0.1/".into(), Vec::new(), token).await,
            Err(Error::InvalidConfiguration)
        ));
    }
}

#[derive(Clone)]
pub(crate) struct MailboxWorker(mpsc::Sender<Request>);

impl MailboxWorker {
    pub async fn start(url: String, root_pem: Vec<u8>, token: AccessToken) -> Result<Self, Error> {
        Self::start_with_pin(url, root_pem, token, None).await
    }
    pub async fn start_with_pin(url: String, root_pem: Vec<u8>, token: AccessToken, pin: Option<[u8; 32]>) -> Result<Self, Error> {
        let (sender, mut receiver) = mpsc::channel(16);
        let (started, ready) = oneshot::channel();
        std::thread::Builder::new()
            .name("hoen-mailbox".into())
            .spawn(move || {
                let result = match pin {
                    Some(pin) => MailboxClient::new_pinned(&url, &root_pem, token, pin),
                    None => MailboxClient::new(&url, &root_pem, token),
                };
                let client = match result {
                    Ok(client) => client,
                    Err(error) => {
                        let _ = started.send(Err(error));
                        return;
                    }
                };
                if started.send(Ok(())).is_err() {
                    return;
                }
                while let Some(request) = receiver.blocking_recv() {
                    // Receiver cancellation intentionally discards only the result.
                    // In particular, an abandoned consumed grant must never be retried.
                    match request {
                        Request::Register(value, reply) => {
                            let _ = reply.send(client.register(&value));
                        }
                        Request::Lookup(identity, reply) => {
                            let _ = reply.send(client.lookup(&identity));
                        }
                        Request::List(reply) => {
                            let _ = reply.send(client.list());
                        }
                        Request::Issue(host, binding, reply) => {
                            let _ = reply.send(client.request_grant(&host, &binding));
                        }
                        Request::Consume(host, token, binding, reply) => {
                            let _ = reply.send(client.consume_grant(token, &binding, &host));
                        }
                    }
                }
            })
            .map_err(|_| Error::InvalidConfiguration)?;
        ready.await.map_err(|_| Error::Unconfirmed)??;
        Ok(Self(sender))
    }

    async fn send(&self, request: Request) -> Result<(), Error> {
        self.0.send(request).await.map_err(|_| Error::Unconfirmed)
    }
    pub async fn register(&self, value: Registration) -> Result<Machine, Error> {
        let (reply, result) = oneshot::channel();
        self.send(Request::Register(value, reply)).await?;
        result.await.map_err(|_| Error::Unconfirmed)?
    }
    pub async fn lookup(&self, host: Identity) -> Result<Machine, Error> {
        let (reply, result) = oneshot::channel();
        self.send(Request::Lookup(host, reply)).await?;
        result.await.map_err(|_| Error::Unconfirmed)?
    }
    pub async fn list(&self) -> Result<Vec<Machine>, Error> {
        let (reply, result) = oneshot::channel();
        self.send(Request::List(reply)).await?;
        result.await.map_err(|_| Error::Unconfirmed)?
    }
    pub async fn issue(&self, host: Identity, binding: [u8; 32]) -> Result<IssuedGrant, Error> {
        let (reply, result) = oneshot::channel();
        self.send(Request::Issue(host, binding, reply)).await?;
        result.await.map_err(|_| Error::Unconfirmed)?
    }
    pub async fn consume(
        &self,
        host: Identity,
        token: GrantToken,
        binding: [u8; 32],
    ) -> Result<ConsumedGrant, Error> {
        let (reply, result) = oneshot::channel();
        self.send(Request::Consume(host, token, binding, reply))
            .await?;
        result.await.map_err(|_| Error::Unconfirmed)?
    }
}
