use concord_protocol::{
    ApprovalMode, CapabilityPermission, EffectClass, EffectPolicyError, ReversibilityClass,
    ReversibilityPolicy,
};
use serde_json::json;

#[test]
fn read_policy_has_a_stable_wire_contract() {
    let policy = ReversibilityPolicy {
        class: ReversibilityClass::ReadOnly,
        reversal_action: None,
        limitations: vec!["The remote source may retain ordinary access logs.".to_owned()],
    };

    policy.validate(EffectClass::NetworkRead).unwrap();
    assert_eq!(
        serde_json::to_value(&policy).unwrap(),
        json!({
            "class": "read_only",
            "limitations": ["The remote source may retain ordinary access logs."]
        })
    );
}

#[test]
fn permission_has_a_stable_wire_contract() {
    let permission = CapabilityPermission {
        selector: "search_papers".to_owned(),
        effect: EffectClass::NetworkRead,
        approval: ApprovalMode::EveryCall,
        data_classes: vec!["public_literature".to_owned()],
    };

    assert_eq!(
        serde_json::to_value(&permission).unwrap(),
        json!({
            "selector": "search_papers",
            "effect": "network_read",
            "approval": "every_call",
            "dataClasses": ["public_literature"]
        })
    );
}

#[test]
fn effectful_work_cannot_masquerade_as_read_only() {
    let policy = ReversibilityPolicy {
        class: ReversibilityClass::ReadOnly,
        reversal_action: None,
        limitations: vec![],
    };

    assert_eq!(
        policy.validate(EffectClass::ExternalWrite),
        Err(EffectPolicyError::EffectCannotClaimReadOnly)
    );
}

#[test]
fn irreversible_work_names_its_residual_facts() {
    let policy = ReversibilityPolicy {
        class: ReversibilityClass::Irreversible,
        reversal_action: Some(
            "Cancel before execution; after completion supersede derived outputs.".to_owned(),
        ),
        limitations: vec![],
    };

    assert_eq!(
        policy.validate(EffectClass::PaidCompute),
        Err(EffectPolicyError::MissingIrreversibleLimitation)
    );
}
