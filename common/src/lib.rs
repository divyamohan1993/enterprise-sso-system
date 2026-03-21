#![forbid(unsafe_code)]
//! common: Shared types for the MILNET SSO system.
//!
//! Provides core domain types including Token, Receipt, DeviceTier,
//! ActionLevel, and other foundational structures used across all crates.

pub mod actions;
pub mod config;
pub mod domain;
pub mod error;
pub mod network;
pub mod types;
