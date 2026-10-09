//! An in-memory transport: endpoints that exchange messages. For tests and
//! dry runs of an adoption before a network adapter is attached.

use std::sync::{Arc, Mutex};

use crate::message::Message;
use crate::transport::Transport;

/// One endpoint: what it sends goes to every other endpoint on its bus, and
/// what it polls is what it has received.
pub struct MemoryTransport {
    author: String,
    inbound: Arc<Mutex<Vec<Message>>>,
    /// Every bus endpoint's inbound queue.
    fanout: Vec<Arc<Mutex<Vec<Message>>>>,
    me: usize,
}

impl MemoryTransport {
    /// Two endpoints: what one sends, the other polls.
    pub fn pair(author_a: &str, author_b: &str) -> (MemoryTransport, MemoryTransport) {
        let mut bus = Self::bus(&[author_a, author_b]);
        let second = bus.pop().unwrap_or_else(|| unreachable!("bus built two endpoints"));
        let first = bus.pop().unwrap_or_else(|| unreachable!("bus built two endpoints"));
        (first, second)
    }

    /// Endpoints on one bus: what any sends, all the others poll. Models a
    /// pubsub topic with several subscribers.
    pub fn bus(authors: &[&str]) -> Vec<MemoryTransport> {
        let queues: Vec<Arc<Mutex<Vec<Message>>>> = authors.iter().map(|_| Arc::new(Mutex::new(Vec::new()))).collect();
        authors
            .iter()
            .enumerate()
            .map(|(me, author)| MemoryTransport { author: author.to_string(), inbound: queues[me].clone(), fanout: queues.clone(), me })
            .collect()
    }
}

impl Transport for MemoryTransport {
    fn author(&self) -> String {
        self.author.clone()
    }

    fn send(&mut self, msg: Message) -> Result<(), String> {
        for (i, queue) in self.fanout.iter().enumerate() {
            if i == self.me {
                continue;
            }
            queue.lock().map_err(|e| e.to_string())?.push(msg.clone());
        }
        Ok(())
    }

    fn poll(&mut self) -> Vec<Message> {
        std::mem::take(&mut *self.inbound.lock().unwrap_or_else(|p| p.into_inner()))
    }
}
