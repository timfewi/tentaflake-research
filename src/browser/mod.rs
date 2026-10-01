//! Isolated Chromium workers. Only fixed read actions and a checked HTTP broker
//! cross the worker boundary; a page never receives a general network tunnel.

pub mod body;
pub mod broker;
pub mod cdp;
pub mod engine;
pub mod launch;
pub mod manager;
pub mod profile;
pub mod read;
pub mod request;
pub mod sandbox;
pub mod session;
pub mod targets;
pub mod wire;
