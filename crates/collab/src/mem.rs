//! An in-memory transport: two endpoints whose messages travel the other
//! way. For tests and dry runs of an adoption before a network adapter is
//! attached.

use std::sync::{Arc, Mutex};

use crate::message::Message;
use crate::transport::Transport;

/// One endpoint of an in-memory pair.
pub struct MemoryTransport {
    author: String,
    inbound: Arc<Mutex<Vec<Message>>>,
    outbound: Arc<Mutex<Vec<Message>>>,
}

impl MemoryTransport {
    /// Two endpoints: what one sends, the other polls.
    pub fn pair(author_a: &str, author_b: &str) -> (MemoryTransport, MemoryTransport) {
        let to_a = Arc::new(Mutex::new(Vec::new()));
        let to_b = Arc::new(Mutex::new(Vec::new()));
        (
            MemoryTransport { author: author_a.to_string(), inbound: to_a.clone(), outbound: to_b.clone() },
            MemoryTransport { author: author_b.to_string(), inbound: to_b, outbound: to_a },
        )
    }
}

impl Transport for MemoryTransport {
    fn author(&self) -> String {
        self.author.clone()
    }

    fn send(&mut self, msg: Message) -> Result<(), String> {
        self.outbound.lock().map_err(|e| e.to_string())?.push(msg);
        Ok(())
    }

    fn poll(&mut self) -> Vec<Message> {
        std::mem::take(&mut *self.inbound.lock().unwrap_or_else(|p| p.into_inner()))
    }
}
