/// High level interfaces for interacting with the Clarity vm
pub mod clarity;

pub mod special;

/// Stacks blockchain specific Clarity database implementations and wrappers
pub mod database;

/// Storage-layer record of a block's Clarity MARF writes
pub mod state_writes;

/// Record of every value a block's execution read from outside itself
pub mod read_witness;

/// Re-execute a block from its read witness alone
pub mod stateless;

/// Evidence for every read-witness entry, and the client-side verifier
pub mod witness_proof;

/// Wire format of a served proof-carrying witness
pub mod witness_wire;

/// Node side: gather a served witness's proofs and headers
pub mod witness_serve;

/// Client side: verify a served witness, re-execute, compare
pub mod witness_client;

#[cfg(test)]
mod tests;
