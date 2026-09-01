use concord_protocol::*;
use serde_json::json;

fn chain() -> Vec<AgentEvent> {
    let created = AgentEvent::build(
        "event-1".into(),
        "run-1".into(),
        0,
        "created".into(),
        AgentEventKind::RunCreated,
        AgentRunStatus::Ready,
        json!({"task": "test"}),
        None,
        "2026-08-12T00:00:00Z".into(),
    )
    .unwrap();
    let requested = AgentEvent::build(
        "event-2".into(),
        "run-1".into(),
        1,
        "request".into(),
        AgentEventKind::ModelRequested,
        created.to_status,
        json!({"requestId": "request-1"}),
        Some(created.event_sha256.clone()),
        "2026-08-12T00:00:01Z".into(),
    )
    .unwrap();
    vec![created, requested]
}

#[test]
fn transition_wire_names_and_retry_semantics_are_stable() {
    assert_eq!(
        serde_json::to_value(AgentEventKind::ModelInterrupted).unwrap(),
        "model_interrupted"
    );
    assert_eq!(
        transition(
            AgentRunStatus::AwaitingModel,
            AgentEventKind::RetryAuthorized
        )
        .unwrap(),
        AgentRunStatus::Ready
    );
    assert!(transition(
        AgentRunStatus::AwaitingModel,
        AgentEventKind::ModelRequested
    )
    .is_err());
}

#[test]
fn replay_verifies_identity_order_status_and_hashes() {
    let events = chain();
    assert_eq!(
        verify_agent_event_chain("run-1", &events).unwrap(),
        AgentRunStatus::AwaitingModel
    );
}

#[test]
fn payload_and_ancestry_tampering_fail_closed() {
    let mut payload_tampered = chain();
    payload_tampered[1].payload = json!({"requestId": "different"});
    assert!(matches!(
        verify_agent_event_chain("run-1", &payload_tampered),
        Err(AgentContractError::EventHashMismatch)
    ));

    let mut ancestry_tampered = chain();
    ancestry_tampered[1].previous_event_sha256 = Some("f".repeat(64));
    ancestry_tampered[1] = AgentEvent::build(
        ancestry_tampered[1].id.clone(),
        ancestry_tampered[1].agent_run_id.clone(),
        ancestry_tampered[1].sequence,
        ancestry_tampered[1].idempotency_key.clone(),
        ancestry_tampered[1].kind,
        ancestry_tampered[1].from_status,
        ancestry_tampered[1].payload.clone(),
        ancestry_tampered[1].previous_event_sha256.clone(),
        ancestry_tampered[1].created_at.clone(),
    )
    .unwrap();
    assert!(matches!(
        verify_agent_event_chain("run-1", &ancestry_tampered),
        Err(AgentContractError::PreviousHashMismatch(1))
    ));
}
