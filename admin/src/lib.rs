#![forbid(unsafe_code)]
//! admin: REST API for MILNET SSO system administration.
//!
//! Provides endpoints for user registration, portal management,
//! device enrollment, audit log inspection, and key transparency queries.

pub mod challenge;
pub mod google_oauth;
pub mod routes;
