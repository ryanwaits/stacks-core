// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Opt-in storage / nested `contract-call?` collector driven by eval-hook
//! notifications. Hex-encodes at emission. Not a [`EvalHook`] object: owned on
//! [`GlobalContext`] so transaction connections do not need a hook lifetime.

use crate::vm::contexts::InvocationContext;
use crate::vm::errors::VmExecutionError;
use crate::vm::events::{
    ContractCallEventData, MapDeleteEventData, MapWriteEventData, StorageEvent, VarSetEventData,
    VmTraceEvent,
};
use crate::vm::hooks::{CallArguments, CallHook};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    VarSet,
    MapSet,
    MapInsert,
    MapDelete,
}

struct PendingStorageCall {
    kind: PendingKind,
    name: String,
    arg_ids: Vec<u64>,
    values: Vec<Option<Value>>,
}

/// One rollback frame of traces, with a running size used by the per-tx cap.
#[derive(Default)]
struct TraceBatch {
    events: Vec<VmTraceEvent>,
    approx_bytes: usize,
}

/// Batch-stacked write / nested-call collector.
#[derive(Default)]
pub struct StorageTraceCollector {
    enabled: bool,
    /// Per-tx cap on live traces. `0` means unlimited.
    max_bytes: usize,
    batches: Vec<TraceBatch>,
    committed: TraceBatch,
    pending: Vec<PendingStorageCall>,
}

impl StorageTraceCollector {
    /// Enable or disable collection. Disabled is a no-op on every method.
    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    /// Per-tx size cap in bytes. `0` (default) is unlimited and is required
    /// for a write log that can reconstruct full Clarity state. A positive
    /// value drops traces past the cap.
    pub fn set_max_bytes(&mut self, max_bytes: usize) {
        self.max_bytes = max_bytes;
    }

    /// Whether collection is on.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Push a new batch (mirrors `GlobalContext::begin` / `begin_read_only`).
    pub fn begin_batch(&mut self) {
        if self.enabled {
            self.batches.push(TraceBatch::default());
        }
    }

    /// Merge the current batch into its parent, or into `committed` at the top.
    pub fn commit_batch(&mut self) {
        if !self.enabled {
            return;
        }
        let Some(mut batch) = self.batches.pop() else {
            return;
        };
        if let Some(parent) = self.batches.last_mut() {
            parent.approx_bytes = parent.approx_bytes.saturating_add(batch.approx_bytes);
            parent.events.append(&mut batch.events);
        } else {
            self.committed = batch;
        }
    }

    /// Drop the current batch, unless it was read-only: then promote (nested
    /// read-only `contract-call?` traces stay visible to the caller).
    pub fn rollback_batch(&mut self, was_read_only: bool) {
        if !self.enabled {
            return;
        }
        let Some(mut batch) = self.batches.pop() else {
            return;
        };
        if was_read_only {
            if let Some(parent) = self.batches.last_mut() {
                parent.approx_bytes = parent.approx_bytes.saturating_add(batch.approx_bytes);
                parent.events.append(&mut batch.events);
            } else {
                self.committed.approx_bytes = self
                    .committed
                    .approx_bytes
                    .saturating_add(batch.approx_bytes);
                self.committed.events.append(&mut batch.events);
            }
        }
    }

    /// Take committed traces for the finished transaction.
    pub fn take_committed(&mut self) -> Vec<VmTraceEvent> {
        self.pending.clear();
        self.batches.clear();
        std::mem::take(&mut self.committed).events
    }

    /// Borrow committed traces without draining.
    pub fn committed(&self) -> &[VmTraceEvent] {
        &self.committed.events
    }

    fn live_bytes(&self) -> usize {
        self.committed.approx_bytes.saturating_add(
            self.batches
                .iter()
                .map(|b| b.approx_bytes)
                .fold(0usize, usize::saturating_add),
        )
    }

    fn current_mut(&mut self) -> &mut TraceBatch {
        self.batches.last_mut().unwrap_or(&mut self.committed)
    }

    fn current_is_truncated(&self) -> bool {
        let events = self
            .batches
            .last()
            .map(|b| b.events.as_slice())
            .unwrap_or(self.committed.events.as_slice());
        matches!(events.last(), Some(VmTraceEvent::Truncated { .. }))
    }

    /// Record an already-built event onto the current batch.
    ///
    /// If a per-tx byte cap is set and this event would exceed it, a single
    /// [`VmTraceEvent::Truncated`] marker is appended instead and further
    /// events increment `dropped`. A truncated nested batch that rolls back
    /// drops the marker with the batch.
    pub fn push_event(&mut self, event: VmTraceEvent) {
        if !self.enabled {
            return;
        }
        if self.current_is_truncated() {
            if let Some(VmTraceEvent::Truncated { dropped }) = self.current_mut().events.last_mut()
            {
                *dropped = dropped.saturating_add(1);
            }
            return;
        }
        let size = event.approx_size();
        let live = self.live_bytes();
        if self.max_bytes > 0 && live.saturating_add(size) > self.max_bytes {
            let truncated = VmTraceEvent::Truncated { dropped: 1 };
            let tsize = truncated.approx_size();
            let target = self.current_mut();
            target.approx_bytes = target.approx_bytes.saturating_add(tsize);
            target.events.push(truncated);
            return;
        }
        let target = self.current_mut();
        target.approx_bytes = target.approx_bytes.saturating_add(size);
        target.events.push(event);
    }

    /// Open a storage builtin call we might emit.
    pub fn will_begin_call(&mut self, call: &CallHook, args: CallArguments) {
        if !self.enabled {
            return;
        }
        let CallHook::Builtin { clarity_name, .. } = call else {
            return;
        };
        let kind = match *clarity_name {
            "var-set" => PendingKind::VarSet,
            "map-set" => PendingKind::MapSet,
            "map-insert" => PendingKind::MapInsert,
            "map-delete" => PendingKind::MapDelete,
            _ => return,
        };
        let name = atom_at(args, 0).unwrap_or_default();
        let (arg_ids, n) = match args {
            CallArguments::Expressions(exprs) => {
                (exprs.iter().map(|e| e.id).collect(), exprs.len())
            }
            CallArguments::Values(vals) => (Vec::new(), vals.len()),
        };
        self.pending.push(PendingStorageCall {
            kind,
            name,
            arg_ids,
            values: vec![None; n],
        });
    }

    /// Fill an evaluated argument by index (apply / apply_evaluated paths).
    pub fn did_evaluate_call_argument(&mut self, arg_index: usize, value: &Value) {
        if !self.enabled {
            return;
        }
        if let Some(frame) = self.pending.last_mut()
            && let Some(slot) = frame.values.get_mut(arg_index)
        {
            *slot = Some(value.clone());
        }
    }

    /// Fill a special-form argument by expression id.
    pub fn did_finish_eval(&mut self, expr: &SymbolicExpression, value: &Value) {
        if !self.enabled {
            return;
        }
        if let Some(frame) = self.pending.last_mut()
            && let Some(index) = frame.arg_ids.iter().position(|id| *id == expr.id)
            && let Some(slot) = frame.values.get_mut(index)
            && slot.is_none()
        {
            *slot = Some(value.clone());
        }
    }

    /// Emit a storage event if this pending call was a matching builtin that
    /// actually changed storage.
    pub fn did_finish_call(
        &mut self,
        invoke_ctx: &InvocationContext,
        call: &CallHook,
        res: &Result<Value, VmExecutionError>,
    ) {
        if !self.enabled {
            return;
        }
        let CallHook::Builtin { clarity_name, .. } = call else {
            return;
        };
        if !matches!(
            *clarity_name,
            "var-set" | "map-set" | "map-insert" | "map-delete"
        ) {
            return;
        }
        let Some(frame) = self.pending.pop() else {
            return;
        };
        let Ok(result) = res else {
            return;
        };
        let contract = invoke_ctx.contract_context.contract_identifier.clone();
        let event = match frame.kind {
            PendingKind::VarSet => {
                let Some(value) = frame.values.get(1).and_then(|v| v.as_ref()) else {
                    return;
                };
                VarSetEventData::try_from_value(contract, frame.name, value)
                    .ok()
                    .map(|data| VmTraceEvent::Storage(StorageEvent::VarSet(data)))
            }
            PendingKind::MapSet => {
                let (Some(key), Some(value)) = (
                    frame.values.get(1).and_then(|v| v.as_ref()),
                    frame.values.get(2).and_then(|v| v.as_ref()),
                ) else {
                    return;
                };
                MapWriteEventData::try_from_values(contract, frame.name, key, value)
                    .ok()
                    .map(|data| VmTraceEvent::Storage(StorageEvent::MapSet(data)))
            }
            PendingKind::MapInsert => {
                if !matches!(result, Value::Bool(true)) {
                    return;
                }
                let (Some(key), Some(value)) = (
                    frame.values.get(1).and_then(|v| v.as_ref()),
                    frame.values.get(2).and_then(|v| v.as_ref()),
                ) else {
                    return;
                };
                MapWriteEventData::try_from_values(contract, frame.name, key, value)
                    .ok()
                    .map(|data| VmTraceEvent::Storage(StorageEvent::MapInsert(data)))
            }
            PendingKind::MapDelete => {
                if !matches!(result, Value::Bool(true)) {
                    return;
                }
                let Some(key) = frame.values.get(1).and_then(|v| v.as_ref()) else {
                    return;
                };
                MapDeleteEventData::try_from_value(contract, frame.name, key)
                    .ok()
                    .map(|data| VmTraceEvent::Storage(StorageEvent::MapDelete(data)))
            }
        };
        if let Some(event) = event {
            self.push_event(event);
        }
    }

    /// Nested `contract-call?` after the callee returns. Arguments are already
    /// evaluated (`atom_value` exprs).
    pub fn record_nested_call(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract_identifier: QualifiedContractIdentifier,
        function_name: String,
        function_args: &[SymbolicExpression],
        result: &Value,
    ) {
        if !self.enabled {
            return;
        }
        let args = function_args
            .iter()
            .filter_map(|expr| expr.match_atom_value());
        let caller = PrincipalData::from(invoke_ctx.contract_context.contract_identifier.clone());
        if let Ok(data) = ContractCallEventData::try_from_values(
            contract_identifier,
            invoke_ctx.sender.clone(),
            caller,
            function_name,
            args,
            result,
        ) {
            self.push_event(VmTraceEvent::ContractCall(data));
        }
    }
}

fn atom_at(args: CallArguments, index: usize) -> Option<String> {
    match args {
        CallArguments::Expressions(exprs) => exprs
            .get(index)
            .and_then(|e| e.match_atom().map(|n| n.to_string())),
        CallArguments::Values(_) => None,
    }
}
