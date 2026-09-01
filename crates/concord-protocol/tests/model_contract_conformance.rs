use concord_protocol::*;
use serde_json::json;

fn request() -> ModelExecutionRequest {
    ModelExecutionRequest {
        contract: MODEL_REQUEST_CONTRACT.to_owned(),
        request_id: "request-1".to_owned(),
        campaign_id: "campaign-1".to_owned(),
        task_class: "scientific_synthesis".to_owned(),
        messages: vec![ModelMessage {
            role: ModelRole::User,
            content: "Compare the recorded observations.".to_owned(),
            name: None,
            tool_call_id: None,
            tool_calls: vec![],
        }],
        tools: vec![],
        response_schema: None,
        context_refs: vec!["object:observation-1@sha256:abc".to_owned()],
        context_receipt_sha256: Some("a".repeat(64)),
        required_capabilities: vec!["text".to_owned()],
        limits: ModelExecutionLimits {
            max_output_tokens: 1024,
            max_tool_calls: 0,
            max_elapsed_seconds: 120,
            max_cost_usd: Some(1.0),
        },
    }
}

#[test]
fn request_wire_format_is_stable() {
    let request = request();
    request.validate().unwrap();
    let value = serde_json::to_value(request).unwrap();
    assert_eq!(value["contract"], MODEL_REQUEST_CONTRACT);
    assert_eq!(value["messages"][0]["role"], "user");
    assert_eq!(value["limits"]["maxOutputTokens"], 1024);
    assert!(value.get("providerId").is_none());
    assert!(value.get("secretRef").is_none());
}

#[test]
fn invalid_message_roles_and_raw_credentials_fail_closed() {
    let mut invalid = request();
    invalid.messages[0].tool_call_id = Some("call-1".to_owned());
    assert!(matches!(
        invalid.validate(),
        Err(ModelContractError::CallIdRequiresToolMessage)
    ));

    let provider = ModelProviderSpec {
        contract: MODEL_PROVIDER_CONTRACT.to_owned(),
        provider_id: "remote".to_owned(),
        transport: ModelTransport::OpenAiCompatible,
        locality: ModelLocality::Remote,
        base_url: Some("https://example.invalid/v1".to_owned()),
        model: "example".to_owned(),
        secret_ref: Some("sk-secret".to_owned()),
        advertised_capabilities: vec!["text".to_owned()],
    };
    assert!(matches!(
        provider.validate(),
        Err(ModelContractError::RawCredentialForbidden)
    ));
}

#[test]
fn context_receipt_binds_selection_and_messages() {
    let receipt = ContextCompilationReceipt {
        contract: CONTEXT_COMPILATION_RECEIPT_CONTRACT.to_owned(),
        id: "context_receipt_request-1".to_owned(),
        campaign_id: "campaign-1".to_owned(),
        request_id: "request-1".to_owned(),
        task_class: "scientific_synthesis".to_owned(),
        compiler_version: CONTEXT_COMPILER_VERSION.to_owned(),
        source_snapshot_sha256: "a".repeat(64),
        policy: ContextCompilationPolicy {
            recent_object_limit: 20,
            recent_action_limit: 12,
            history_message_limit: 12,
            program_character_limit: 12_000,
            history_message_character_limit: 4_000,
            lineage_traversal_limit: 64,
            retained_lineage_checkpoint_limit: 3,
            excluded_type_names: vec![CONTEXT_COMPILATION_RECEIPT_CONTRACT.to_owned()],
        },
        included_context_refs: vec!["object:included@sha256:one".to_owned()],
        omissions: vec![ContextOmission {
            source_ref: "object:omitted@sha256:two".to_owned(),
            reason: "older_than_limit".to_owned(),
        }],
        truncations: vec![ContextTruncation {
            source_ref: "object:included@sha256:one".to_owned(),
            original_characters: 5_000,
            retained_characters: 4_000,
            reason: "message_character_limit".to_owned(),
        }],
        compiled_message_count: 3,
        compiled_message_sha256: "b".repeat(64),
        built_from_canonical_records: true,
        recursive_summary_generation: 0,
        authoritative: false,
        created_at: "2026-08-23T00:00:00Z".to_owned(),
        receipt_sha256: String::new(),
    }
    .seal()
    .unwrap();
    receipt.validate().unwrap();
    let mut tampered = receipt;
    tampered.omissions[0].reason = "different".to_owned();
    assert!(matches!(
        tampered.validate(),
        Err(ModelContractError::ContextReceiptHashMismatch)
    ));
}

#[test]
fn response_usage_and_tool_arguments_are_validated() {
    let response = ModelExecutionResponse {
        contract: MODEL_RESPONSE_CONTRACT.to_owned(),
        request_id: "request-1".to_owned(),
        provider_id: "provider-1".to_owned(),
        model: "model-1".to_owned(),
        output: vec![ModelOutputBlock::ToolCall {
            id: "call-1".to_owned(),
            name: "read_object".to_owned(),
            arguments: json!({"id": "observation-1"}),
        }],
        finish_reason: Some("tool_calls".to_owned()),
        usage: ModelUsage {
            input_tokens: Some(10),
            output_tokens: Some(4),
            total_tokens: Some(14),
        },
    };
    response.validate().unwrap();
    let mut invalid = response;
    invalid.usage.total_tokens = Some(15);
    assert!(matches!(
        invalid.validate(),
        Err(ModelContractError::InconsistentTokenUsage)
    ));
}
