use crate::network::PolicyState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::Mutex;
use tracing::error;

const DEFAULT_STATE_PATH: &str = "/var/run/coentrovpn/server_helper_state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentSession {
    pub session_id: String,
    pub interface: String,
    pub policy: PolicyState,
}

#[derive(Debug)]
pub struct Persistence {
    path: PathBuf,
    state: Mutex<HashMap<String, PersistentSession>>,
}

impl Persistence {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path: path.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_PATH)),
            state: Mutex::new(HashMap::new()),
        }
    }

    pub async fn load(&self) {
        let path = self.path.clone();
        let contents = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    error!(file = %path.display(), "failed to read persistence file: {err}");
                }
                return;
            }
        };

        match serde_json::from_slice::<Vec<PersistentSession>>(&contents) {
            Ok(entries) => {
                let mut guard = self.state.lock().await;
                guard.clear();
                for entry in entries {
                    guard.insert(entry.session_id.clone(), entry);
                }
            }
            Err(err) => {
                error!(file = %path.display(), "failed to parse persistence file: {err}");
            }
        }
    }

    async fn flush(&self) {
        let guard = self.state.lock().await;
        if guard.is_empty() {
            if fs::remove_file(&self.path).await.is_err() {
                // Ignore errors when removing non-existent file
            }
            return;
        }

        if let Some(parent) = self.path.parent() {
            if let Err(err) = fs::create_dir_all(parent).await {
                error!(dir = %parent.display(), "failed to create persistence directory: {err}");
                return;
            }
        }

        let entries: Vec<_> = guard.values().cloned().collect();
        drop(guard);

        match serde_json::to_vec_pretty(&entries) {
            Ok(serialized) => {
                if let Err(err) = fs::write(&self.path, serialized).await {
                    error!(file = %self.path.display(), "failed to write persistence file: {err}");
                }
            }
            Err(err) => error!("failed to serialize persistence state: {err}"),
        }
    }

    pub async fn register_session(&self, session_id: &str, interface: &str, policy: PolicyState) {
        let mut guard = self.state.lock().await;
        guard.insert(
            session_id.to_string(),
            PersistentSession {
                session_id: session_id.to_string(),
                interface: interface.to_string(),
                policy,
            },
        );
        drop(guard);
        self.flush().await;
    }

    pub async fn remove_session(&self, session_id: &str) {
        let mut guard = self.state.lock().await;
        guard.remove(session_id);
        drop(guard);
        self.flush().await;
    }

    pub async fn drain(&self) -> Vec<PersistentSession> {
        let mut guard = self.state.lock().await;
        let entries: Vec<_> = guard.values().cloned().collect();
        guard.clear();
        drop(guard);
        self.flush().await;
        entries
    }
}

impl Default for Persistence {
    fn default() -> Self {
        Self::new(None)
    }
}
