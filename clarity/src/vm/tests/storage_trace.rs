// Copyright (C) 2026 Stacks Open Internet Foundation

use stacks_common::types::StacksEpochId;

use crate::vm::ClarityVersion;
use crate::vm::contexts::OwnedEnvironment;
use crate::vm::database::MemoryBackingStore;
use crate::vm::events::{StorageEvent, VarSetEventData, VmTraceEvent};
use crate::vm::hooks::storage::StorageTraceCollector;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};

const STORE: &str = r#"
(define-data-var n uint u0)
(define-map kv uint uint)
(define-public (set-n (x uint))
  (ok (var-set n x)))
(define-public (write-map (k uint) (v uint))
  (begin
    (map-set kv k v)
    (ok true)))
(define-public (insert-map (k uint) (v uint))
  (ok (map-insert kv k v)))
(define-public (delete-map (k uint))
  (ok (map-delete kv k)))
(define-public (print-and-set (x uint))
  (begin
    (print x)
    (ok (var-set n x))))
(define-public (fail-after-set)
  (begin
    (var-set n u9)
    (err u1)))
"#;

const CALLEE: &str = r#"
(define-data-var n uint u0)
(define-public (inc)
  (ok (var-set n (+ (var-get n) u1))))
(define-public (fail-after-set)
  (begin
    (var-set n u9)
    (err u1)))
(define-read-only (peek)
  (var-get n))
"#;

const CALLER: &str = r#"
(define-public (go)
  (contract-call? .callee inc))
(define-public (observe-fail)
  (ok (contract-call? .callee fail-after-set)))
(define-public (peek-inner)
  (ok (contract-call? .callee peek)))
"#;

fn issuer() -> PrincipalData {
    QualifiedContractIdentifier::local("store")
        .unwrap()
        .issuer
        .into()
}

fn exec(
    env: &mut OwnedEnvironment,
    contract: &QualifiedContractIdentifier,
    name: &str,
    args: Vec<Value>,
) -> (Value, Vec<crate::vm::events::StacksTransactionEvent>) {
    let args: Vec<_> = args
        .into_iter()
        .map(crate::vm::SymbolicExpression::atom_value)
        .collect();
    let (value, _assets, events) = env
        .execute_transaction(issuer(), None, contract.clone(), name, &args)
        .unwrap();
    (value, events)
}

fn store_id() -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::local("store").unwrap()
}

fn init_store(env: &mut OwnedEnvironment) {
    env.initialize_versioned_contract(store_id(), ClarityVersion::Clarity2, STORE, None)
        .unwrap();
}

fn is_ok_true(v: &Value) -> bool {
    matches!(v, Value::Response(r) if r.committed)
}

#[test]
fn off_emits_nothing() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env);
    let (value, events) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(3)]);
    assert!(is_ok_true(&value));
    assert!(env.vm_trace_events().is_empty());
    assert!(events.is_empty());
}

#[test]
fn var_set_isolated_from_classic_events() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env);
    env.set_emit_vm_trace(true);

    let (value, events) = exec(&mut env, &store_id(), "print-and-set", vec![Value::UInt(4)]);
    assert!(is_ok_true(&value));
    assert_eq!(events.len(), 1, "print stays in classic events[]");
    assert_eq!(env.vm_trace_events().len(), 1);
    match &env.vm_trace_events()[0] {
        VmTraceEvent::Storage(StorageEvent::VarSet(data)) => {
            assert_eq!(data.var_name, "n");
            assert_eq!(data.raw_value, "0x0100000000000000000000000000000004");
        }
        other => panic!("expected var_set, got {other:?}"),
    }
}

#[test]
fn map_insert_delete_only_on_change() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env);
    env.set_emit_vm_trace(true);

    let (value, _) = exec(
        &mut env,
        &store_id(),
        "insert-map",
        vec![Value::UInt(1), Value::UInt(2)],
    );
    assert!(is_ok_true(&value));
    assert_eq!(env.vm_trace_events().len(), 1);
    assert!(matches!(
        env.vm_trace_events()[0],
        VmTraceEvent::Storage(StorageEvent::MapInsert(_))
    ));

    let (value, _) = exec(
        &mut env,
        &store_id(),
        "insert-map",
        vec![Value::UInt(1), Value::UInt(3)],
    );
    assert!(is_ok_true(&value));
    assert!(
        env.vm_trace_events().is_empty(),
        "no-op insert must not emit"
    );

    let (value, _) = exec(&mut env, &store_id(), "delete-map", vec![Value::UInt(1)]);
    assert!(is_ok_true(&value));
    assert!(matches!(
        env.vm_trace_events()[0],
        VmTraceEvent::Storage(StorageEvent::MapDelete(_))
    ));
}

#[test]
fn failed_inner_drops_writes_keeps_call_if_caller_commits() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    let caller = QualifiedContractIdentifier::local("caller").unwrap();
    env.initialize_versioned_contract(callee.clone(), ClarityVersion::Clarity2, CALLEE, None)
        .unwrap();
    env.initialize_versioned_contract(caller.clone(), ClarityVersion::Clarity2, CALLER, None)
        .unwrap();
    env.set_emit_vm_trace(true);

    let (value, _) = exec(&mut env, &caller, "observe-fail", vec![]);
    assert!(is_ok_true(&value));
    let traces = env.vm_trace_events();
    assert!(
        traces
            .iter()
            .any(|e| matches!(e, VmTraceEvent::ContractCall(_))),
        "nested call kept: {traces:?}"
    );
    assert!(
        traces
            .iter()
            .all(|e| !matches!(e, VmTraceEvent::Storage(_))),
        "inner writes rolled back: {traces:?}"
    );
}

#[test]
fn nested_call_then_storage_order() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    let caller = QualifiedContractIdentifier::local("caller").unwrap();
    env.initialize_versioned_contract(callee, ClarityVersion::Clarity2, CALLEE, None)
        .unwrap();
    env.initialize_versioned_contract(caller.clone(), ClarityVersion::Clarity2, CALLER, None)
        .unwrap();
    env.set_emit_vm_trace(true);

    let (value, _) = exec(&mut env, &caller, "go", vec![]);
    assert!(is_ok_true(&value));
    let traces = env.vm_trace_events();
    assert_eq!(traces.len(), 2, "{traces:?}");
    assert!(
        matches!(traces[0], VmTraceEvent::Storage(StorageEvent::VarSet(_))),
        "callee write first: {traces:?}"
    );
    assert!(
        matches!(traces[1], VmTraceEvent::ContractCall(_)),
        "enclosing call after inner writes: {traces:?}"
    );
}

#[test]
fn read_only_nested_call_kept() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    let caller = QualifiedContractIdentifier::local("caller").unwrap();
    env.initialize_versioned_contract(callee, ClarityVersion::Clarity2, CALLEE, None)
        .unwrap();
    env.initialize_versioned_contract(caller.clone(), ClarityVersion::Clarity2, CALLER, None)
        .unwrap();
    env.set_emit_vm_trace(true);

    let (value, _) = exec(&mut env, &caller, "peek-inner", vec![]);
    assert!(is_ok_true(&value));
    assert!(
        env.vm_trace_events()
            .iter()
            .any(|e| matches!(e, VmTraceEvent::ContractCall(_))),
        "read-only nested call kept: {:?}",
        env.vm_trace_events()
    );
}

#[test]
fn define_data_var_init_emits_var_set() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    env.set_emit_vm_trace(true);
    init_store(&mut env);
    let traces = env.vm_trace_events();
    assert!(
        traces.iter().any(|e| matches!(
            e,
            VmTraceEvent::Storage(StorageEvent::VarSet(d)) if d.var_name == "n"
        )),
        "deploy-time var init: {traces:?}"
    );
}

#[test]
fn cost_identity_flag_on_or_off() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env);
    let (off_value, off_events) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(8)]);
    let off_cost = env.get_cost_total();

    env.set_emit_vm_trace(true);
    let (on_value, on_events) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(8)]);
    let on_cost = env.get_cost_total();

    assert_eq!(off_value, on_value);
    assert_eq!(off_events, on_events);
    assert_eq!(off_cost, on_cost);
}

#[test]
fn failed_public_drops_own_writes() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env);
    env.set_emit_vm_trace(true);
    let (value, _) = exec(&mut env, &store_id(), "fail-after-set", vec![]);
    assert!(!is_ok_true(&value));
    assert!(
        env.vm_trace_events().is_empty(),
        "aborted public fn drops traces: {:?}",
        env.vm_trace_events()
    );
}

fn var_set_trace(n: u128) -> VmTraceEvent {
    VmTraceEvent::Storage(StorageEvent::VarSet(
        VarSetEventData::try_from_value(store_id(), "n".into(), &Value::UInt(n)).unwrap(),
    ))
}

#[test]
fn unlimited_cap_keeps_every_event() {
    let mut c = StorageTraceCollector::default();
    c.set_enabled(true);
    c.set_max_bytes(0);
    for i in 0..50 {
        c.push_event(var_set_trace(i));
    }
    assert_eq!(c.committed().len(), 50);
    assert!(
        c.committed()
            .iter()
            .all(|e| !matches!(e, VmTraceEvent::Truncated { .. }))
    );
}

#[test]
fn positive_cap_emits_truncated_and_drops_rest() {
    let mut c = StorageTraceCollector::default();
    c.set_enabled(true);
    let first = var_set_trace(1);
    c.set_max_bytes(first.approx_size().saturating_add(8));
    c.push_event(first);
    c.push_event(var_set_trace(2));
    c.push_event(var_set_trace(3));
    assert_eq!(c.committed().len(), 2, "{:?}", c.committed());
    assert!(matches!(
        c.committed()[0],
        VmTraceEvent::Storage(StorageEvent::VarSet(_))
    ));
    assert!(matches!(
        c.committed()[1],
        VmTraceEvent::Truncated { dropped: 2 }
    ));
}

#[test]
fn rolled_back_truncated_batch_does_not_poison_parent() {
    let mut c = StorageTraceCollector::default();
    c.set_enabled(true);
    c.set_max_bytes(1);
    c.begin_batch();
    c.begin_batch();
    c.push_event(var_set_trace(1));
    assert!(c.committed().last().is_none());
    c.rollback_batch(false);
    c.set_max_bytes(0);
    c.push_event(var_set_trace(9));
    c.commit_batch();
    assert_eq!(c.committed().len(), 1);
    assert!(matches!(
        c.committed()[0],
        VmTraceEvent::Storage(StorageEvent::VarSet(_))
    ));
}

#[test]
fn env_unlimited_by_default_records_writes() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env);
    env.set_emit_vm_trace(true);
    env.set_vm_trace_max_bytes(0);
    let (value, _) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(3)]);
    assert!(is_ok_true(&value));
    assert!(matches!(
        env.vm_trace_events()[0],
        VmTraceEvent::Storage(StorageEvent::VarSet(_))
    ));
}

#[test]
fn env_tiny_cap_emits_truncated() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env);
    env.set_emit_vm_trace(true);
    env.set_vm_trace_max_bytes(1);
    let (value, _) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(3)]);
    assert!(is_ok_true(&value));
    assert_eq!(env.vm_trace_events().len(), 1);
    assert!(matches!(
        env.vm_trace_events()[0],
        VmTraceEvent::Truncated { dropped: 1 }
    ));
}
