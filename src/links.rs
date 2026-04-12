//! Ephemeral Links Module
//!
//! Provides time-limited and usage-limited sharing links for Polygone-Drive.
//! Links can expire based on time (TTL) or number of downloads.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralLink {
    pub map_data: Vec<u8>,
    pub created_at: u64,
    pub ttl_seconds: u64,
    pub max_downloads: u32,
    pub downloads: u32,
}

impl EphemeralLink {
    pub fn new(map_data: Vec<u8>, ttl_seconds: u64, max_downloads: u32) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            map_data,
            created_at: now,
            ttl_seconds,
            max_downloads,
            downloads: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.ttl_seconds > 0 && now > self.created_at + self.ttl_seconds {
            return true;
        }

        if self.max_downloads > 0 && self.downloads >= self.max_downloads {
            return true;
        }

        false
    }

    pub fn record_download(&mut self) {
        self.downloads += 1;
    }

    pub fn time_remaining(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.ttl_seconds == 0 {
            return u64::MAX;
        }

        let elapsed = now.saturating_sub(self.created_at);
        self.ttl_seconds.saturating_sub(elapsed)
    }

    pub fn downloads_remaining(&self) -> u32 {
        if self.max_downloads == 0 {
            return u32::MAX;
        }
        self.max_downloads.saturating_sub(self.downloads)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkType {
    Permanent,
    EphemeralTime {
        ttl_seconds: u64,
    },
    EphemeralUsage {
        max_downloads: u32,
    },
    EphemeralBoth {
        ttl_seconds: u64,
        max_downloads: u32,
    },
}

impl LinkType {
    pub fn from_flags(ttl_seconds: u64, max_downloads: u32) -> Self {
        match (ttl_seconds > 0, max_downloads > 0) {
            (true, true) => LinkType::EphemeralBoth {
                ttl_seconds,
                max_downloads,
            },
            (true, false) => LinkType::EphemeralTime { ttl_seconds },
            (false, true) => LinkType::EphemeralUsage { max_downloads },
            (false, false) => LinkType::Permanent,
        }
    }
}

pub struct LinkManager {
    active_links: std::collections::HashMap<String, EphemeralLink>,
}

impl LinkManager {
    pub fn new() -> Self {
        Self {
            active_links: std::collections::HashMap::new(),
        }
    }

    pub fn create_link(&mut self, id: String, map_data: Vec<u8>, link_type: LinkType) -> String {
        let link = match link_type {
            LinkType::Permanent => {
                return base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    &map_data,
                );
            }
            LinkType::EphemeralTime { ttl_seconds } => EphemeralLink::new(map_data, ttl_seconds, 0),
            LinkType::EphemeralUsage { max_downloads } => {
                EphemeralLink::new(map_data, 0, max_downloads)
            }
            LinkType::EphemeralBoth {
                ttl_seconds,
                max_downloads,
            } => EphemeralLink::new(map_data, ttl_seconds, max_downloads),
            LinkType::Permanent => unreachable!(),
        };

        let token = format!("eph_{}", uuid::Uuid::new_v4());
        self.active_links.insert(token.clone(), link);
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            token.as_bytes(),
        )
    }

    pub fn validate_link(&mut self, token: &str) -> Option<Vec<u8>> {
        if token.starts_with("eph_") {
            if let Ok(decoded) =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token)
            {
                if let Ok(key) = String::from_utf8(decoded) {
                    if let Some(link) = self.active_links.get_mut(&key) {
                        if !link.is_expired() {
                            link.record_download();
                            return Some(link.map_data.clone());
                        }
                    }
                }
            }
            None
        } else {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token).ok()
        }
    }

    pub fn cleanup_expired(&mut self) {
        self.active_links.retain(|_, link| !link.is_expired());
    }
}

impl Default for LinkManager {
    fn default() -> Self {
        Self::new()
    }
}
