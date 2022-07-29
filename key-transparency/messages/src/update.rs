use vkd::storage::types::{AkdLabel, AkdValue};

/// A client request in a format understandable by `vkd`.
pub type UpdateRequest = (AkdLabel, AkdValue);

/// A batch of requests.
pub type Batch = Vec<UpdateRequest>;
