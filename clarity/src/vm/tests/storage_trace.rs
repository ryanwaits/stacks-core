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

// ---------------------------------------------------------------------------
// A write row must record the key and value the storage builtin itself
// evaluated, never a value from a call nested inside its arguments or from a
// callee contract whose expression ids collide with the builtin's.
// ---------------------------------------------------------------------------

const WRITES: &str = r#"
(define-data-var c uint u10)
(define-data-var n uint u0)
(define-map kv uint uint)
(define-map reserve principal uint)
(define-private (get-reserve (who principal))
  (default-to u0 (map-get? reserve who)))
(define-private (mix (a uint) (b uint) (d uint))
  (+ (* a u100) (* b u10) d))
(define-public (bump)
  (ok (var-set c (+ (var-get c) u1))))
(define-public (add-reserve (who principal) (amount uint))
  (ok (map-set reserve who (+ amount (get-reserve who)))))
(define-public (set-sum-value (k uint))
  (ok (map-set kv k (+ u1 u2 u3))))
(define-public (set-sum-key (a uint) (b uint))
  (ok (map-set kv (+ a b) u7)))
(define-public (insert-sum-value (k uint))
  (ok (map-insert kv k (+ u1 u2 u3))))
(define-public (insert-sum-key (a uint) (b uint))
  (ok (map-insert kv (+ a b) u7)))
(define-public (insert-reserve (who principal) (amount uint))
  (ok (map-insert reserve who (+ amount (get-reserve who)))))
(define-public (delete-sum-key (a uint) (b uint))
  (ok (map-delete kv (+ a b))))
(define-public (seed (k uint) (v uint))
  (ok (map-set kv k v)))
(define-public (write-inside-write (k uint))
  (ok (map-set kv k (begin (var-set n u2) u5))))
(define-public (set-mixed)
  (ok (map-set kv (mix u1 u2 u3) (mix u4 u5 u6))))
(define-public (insert-mixed)
  (ok (map-insert kv (mix u1 u2 u3) (mix u4 u5 u6))))
(define-public (delete-mixed)
  (ok (map-delete kv (mix u1 u2 u3))))
"#;

// The callee's top-level prefix is token-for-token the same shape as the
// caller's, so `k` and `u40` carry the ids of the caller's key and value
// arguments.
const TWIN: &str = r#"
(define-map kv uint uint)
(define-public (go (k uint))
  (ok (+ k k u40)))
"#;

const OUTER_SET: &str = r#"
(define-map kv uint uint)
(define-public (go (k uint))
  (ok (map-set kv k (unwrap-panic (contract-call? .twin go k)))))
"#;

const OUTER_INSERT: &str = r#"
(define-map kv uint uint)
(define-public (go (k uint))
  (ok (map-insert kv k (unwrap-panic (contract-call? .twin go k)))))
"#;

// `u40` carries the id of the caller's map-delete key argument.
const TWIN_DEL: &str = r#"
(define-map kv uint uint)
(define-public (go (k uint))
  (ok (+ k u40)))
"#;

const OUTER_DELETE: &str = r#"
(define-map kv uint uint)
(define-public (go (k uint))
  (ok (map-delete kv (unwrap-panic (contract-call? .twin-del go k)))))
(define-public (seed (k uint) (v uint))
  (ok (map-set kv k v)))
"#;

const FT_TOKEN: &str = r#"
(define-public (get-decimals)
  (ok u6))
"#;

const VAULT: &str = r#"
(define-trait ft-trait ((get-decimals () (response uint uint))))
(define-map reserve principal uint)
(define-read-only (get-reserve (token principal))
  (default-to u0 (map-get? reserve token)))
(define-public (add-to-reserve (token <ft-trait>) (amount uint))
  (ok (map-set reserve (contract-of token) (+ amount (get-reserve (contract-of token))))))
"#;

const ROUTER: &str = r#"
(define-public (route (amount uint))
  (contract-call? .vault add-to-reserve .token amount))
"#;

/// Transient issuer (`S1G2081040…`): every test contract's issuer and the tx sender.
const ISSUER_HEX: &str = "0x05010101010101010101010101010101010101010101";
/// `<issuer>.token`.
const TOKEN_HEX: &str = "0x0601010101010101010101010101010101010101010105746f6b656e";

fn uint_hex(n: u128) -> String {
    format!("0x01{n:032x}")
}

fn deploy(env: &mut OwnedEnvironment, name: &str, src: &str) -> QualifiedContractIdentifier {
    let id = QualifiedContractIdentifier::local(name).unwrap();
    env.initialize_versioned_contract(id.clone(), ClarityVersion::Clarity2, src, None)
        .unwrap();
    id
}

/// One line per storage write of the last transaction, in order.
fn writes(env: &OwnedEnvironment) -> Vec<String> {
    env.vm_trace_events()
        .iter()
        .filter_map(|e| match e {
            VmTraceEvent::Storage(StorageEvent::VarSet(d)) => {
                Some(format!("var_set {} {}", d.var_name, d.raw_value))
            }
            VmTraceEvent::Storage(StorageEvent::MapSet(d)) => Some(format!(
                "map_set {} {} {}",
                d.map_name, d.raw_key, d.raw_value
            )),
            VmTraceEvent::Storage(StorageEvent::MapInsert(d)) => Some(format!(
                "map_insert {} {} {}",
                d.map_name, d.raw_key, d.raw_value
            )),
            VmTraceEvent::Storage(StorageEvent::MapDelete(d)) => {
                Some(format!("map_delete {} {}", d.map_name, d.raw_key))
            }
            _ => None,
        })
        .collect()
}

fn writes_env(
    marf: &mut MemoryBackingStore,
) -> (OwnedEnvironment<'_, '_>, QualifiedContractIdentifier) {
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    let id = deploy(&mut env, "writes", WRITES);
    env.set_emit_vm_trace(true);
    (env, id)
}

fn run_ok(
    env: &mut OwnedEnvironment,
    contract: &QualifiedContractIdentifier,
    name: &str,
    args: Vec<Value>,
) {
    let (value, _) = exec(env, contract, name, args);
    assert!(is_ok_true(&value), "{name} -> {value:?}");
}

#[test]
fn var_set_value_from_nested_arithmetic() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(&mut env, &id, "bump", vec![]);
    assert_eq!(writes(&env), vec![format!("var_set c {}", uint_hex(11))]);
}

#[test]
fn map_set_key_survives_user_fn_reading_old_value() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(
        &mut env,
        &id,
        "add-reserve",
        vec![Value::from(issuer()), Value::UInt(5)],
    );
    assert_eq!(
        writes(&env),
        vec![format!("map_set reserve {ISSUER_HEX} {}", uint_hex(5))]
    );
    run_ok(
        &mut env,
        &id,
        "add-reserve",
        vec![Value::from(issuer()), Value::UInt(7)],
    );
    assert_eq!(
        writes(&env),
        vec![format!("map_set reserve {ISSUER_HEX} {}", uint_hex(12))]
    );
}

#[test]
fn map_set_value_from_three_arg_builtin() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(&mut env, &id, "set-sum-value", vec![Value::UInt(1)]);
    assert_eq!(
        writes(&env),
        vec![format!("map_set kv {} {}", uint_hex(1), uint_hex(6))]
    );
}

#[test]
fn map_set_key_from_nested_arithmetic() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(
        &mut env,
        &id,
        "set-sum-key",
        vec![Value::UInt(2), Value::UInt(3)],
    );
    assert_eq!(
        writes(&env),
        vec![format!("map_set kv {} {}", uint_hex(5), uint_hex(7))]
    );
}

#[test]
fn map_insert_key_and_value_from_nested_calls() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(&mut env, &id, "insert-sum-value", vec![Value::UInt(1)]);
    assert_eq!(
        writes(&env),
        vec![format!("map_insert kv {} {}", uint_hex(1), uint_hex(6))]
    );
    run_ok(
        &mut env,
        &id,
        "insert-sum-key",
        vec![Value::UInt(2), Value::UInt(3)],
    );
    assert_eq!(
        writes(&env),
        vec![format!("map_insert kv {} {}", uint_hex(5), uint_hex(7))]
    );
    run_ok(
        &mut env,
        &id,
        "insert-reserve",
        vec![Value::from(issuer()), Value::UInt(4)],
    );
    assert_eq!(
        writes(&env),
        vec![format!("map_insert reserve {ISSUER_HEX} {}", uint_hex(4))]
    );
}

#[test]
fn map_delete_key_from_nested_arithmetic() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(&mut env, &id, "seed", vec![Value::UInt(5), Value::UInt(9)]);
    run_ok(
        &mut env,
        &id,
        "delete-sum-key",
        vec![Value::UInt(2), Value::UInt(3)],
    );
    assert_eq!(writes(&env), vec![format!("map_delete kv {}", uint_hex(5))]);
}

#[test]
fn write_nested_in_write_value_records_both_in_order() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(&mut env, &id, "write-inside-write", vec![Value::UInt(1)]);
    assert_eq!(
        writes(&env),
        vec![
            format!("var_set n {}", uint_hex(2)),
            format!("map_set kv {} {}", uint_hex(1), uint_hex(5)),
        ]
    );
}

#[test]
fn three_arg_user_fns_in_key_and_value() {
    let mut marf = MemoryBackingStore::new();
    let (mut env, id) = writes_env(&mut marf);
    run_ok(&mut env, &id, "set-mixed", vec![]);
    assert_eq!(
        writes(&env),
        vec![format!("map_set kv {} {}", uint_hex(123), uint_hex(456))]
    );
    run_ok(&mut env, &id, "delete-mixed", vec![]);
    assert_eq!(
        writes(&env),
        vec![format!("map_delete kv {}", uint_hex(123))]
    );
    run_ok(&mut env, &id, "insert-mixed", vec![]);
    assert_eq!(
        writes(&env),
        vec![format!("map_insert kv {} {}", uint_hex(123), uint_hex(456))]
    );
}

#[test]
fn trait_param_principal_key_mirrors_amm_vault() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    deploy(&mut env, "token", FT_TOKEN);
    deploy(&mut env, "vault", VAULT);
    let router = deploy(&mut env, "router", ROUTER);
    env.set_emit_vm_trace(true);

    run_ok(&mut env, &router, "route", vec![Value::UInt(5)]);
    assert_eq!(
        writes(&env),
        vec![format!("map_set reserve {TOKEN_HEX} {}", uint_hex(5))]
    );
    run_ok(&mut env, &router, "route", vec![Value::UInt(7)]);
    assert_eq!(
        writes(&env),
        vec![format!("map_set reserve {TOKEN_HEX} {}", uint_hex(12))]
    );
}

#[test]
fn map_set_value_ignores_callee_with_colliding_expr_ids() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    deploy(&mut env, "twin", TWIN);
    let outer = deploy(&mut env, "outer-set", OUTER_SET);
    env.set_emit_vm_trace(true);
    run_ok(&mut env, &outer, "go", vec![Value::UInt(1)]);
    assert_eq!(
        writes(&env),
        vec![format!("map_set kv {} {}", uint_hex(1), uint_hex(42))]
    );
}

#[test]
fn map_insert_value_ignores_callee_with_colliding_expr_ids() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    deploy(&mut env, "twin", TWIN);
    let outer = deploy(&mut env, "outer-insert", OUTER_INSERT);
    env.set_emit_vm_trace(true);
    run_ok(&mut env, &outer, "go", vec![Value::UInt(1)]);
    assert_eq!(
        writes(&env),
        vec![format!("map_insert kv {} {}", uint_hex(1), uint_hex(42))]
    );
}

#[test]
fn map_delete_key_ignores_callee_with_colliding_expr_ids() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    deploy(&mut env, "twin-del", TWIN_DEL);
    let outer = deploy(&mut env, "outer-delete", OUTER_DELETE);
    env.set_emit_vm_trace(true);
    run_ok(
        &mut env,
        &outer,
        "seed",
        vec![Value::UInt(41), Value::UInt(7)],
    );
    run_ok(&mut env, &outer, "go", vec![Value::UInt(1)]);
    assert_eq!(
        writes(&env),
        vec![format!("map_delete kv {}", uint_hex(41))]
    );
}
