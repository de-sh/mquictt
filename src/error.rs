use tokio::sync::mpsc;

use crate::client;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Quiche Error: {0}")]
    Quiche(#[from] quiche::Error),
    #[error("Client Event Send Error: {0}")]
    EventSendError(#[from] mpsc::error::SendError<(u64, client::ClientEvent)>),
    #[error("Subscriber Recv Error")]
    SubscriberRecvError,
    #[error("MQTT Error")]
    MQTT(mqttbytes::Error),
}
