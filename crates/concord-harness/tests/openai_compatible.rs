use concord_harness::{normalize_openai_chat_response, openai_chat_payload};
use concord_protocol::{
    ModelExecutionLimits, ModelExecutionRequest, ModelLocality, ModelMessage, ModelMessageToolCall,
    ModelProviderSpec, ModelRole, ModelToolDefinition, ModelTransport, MODEL_PROVIDER_CONTRACT,
    MODEL_REQUEST_CONTRACT, MODEL_RESPONSE_CONTRACT,
};
use serde_json::{json, Value};

fn request() -> ModelExecutionRequest {
    ModelExecutionRequest {
        contract: MODEL_REQUEST_CONTRACT.to_owned(),
        request_id: "request-1".to_owned(),
        campaign_id: "campaign-1".to_owned(),
        task_class: "scientific_synthesis".to_owned(),
        messages: vec![ModelMessage {
            role: ModelRole::User,
            content: "Compare the two recorded observations.".to_owned(),
            name: None,
            tool_call_id: None,
            tool_calls: vec![],
        }],
        tools: vec![ModelToolDefinition {
            name: "read_campaign_object".to_owned(),
            description: "Read one typed campaign object by identity.".to_owned(),
            input_schema: json!({"type": "object"}),
        }],
        response_schema: None,
        context_refs: vec!["object:observation-1@sha256:abc".to_owned()],
        context_receipt_sha256: None,
        required_capabilities: vec!["text".to_owned(), "tool_calling".to_owned()],
        limits: ModelExecutionLimits {
            max_output_tokens: 1024,
            max_tool_calls: 4,
            max_elapsed_seconds: 120,
            max_cost_usd: Some(1.0),
        },
    }
}

#[test]
fn provider_identity_stays_outside_the_canonical_request() {
    let request = request();
    let remote = ModelProviderSpec {
        contract: MODEL_PROVIDER_CONTRACT.to_owned(),
        provider_id: "remote-compatible".to_owned(),
        transport: ModelTransport::OpenAiCompatible,
        locality: ModelLocality::Remote,
        base_url: Some("https://example.invalid/v1".to_owned()),
        model: "remote-model".to_owned(),
        secret_ref: Some("env:REMOTE_MODEL_API_KEY".to_owned()),
        advertised_capabilities: vec!["text".to_owned(), "tool_calling".to_owned()],
    };
    let local = ModelProviderSpec {
        provider_id: "local-compatible".to_owned(),
        locality: ModelLocality::Local,
        base_url: Some("http://127.0.0.1:8000/v1".to_owned()),
        model: "local-model".to_owned(),
        secret_ref: None,
        ..remote.clone()
    };
    remote.validate().unwrap();
    local.validate().unwrap();
    let remote_payload = openai_chat_payload(&request, &remote.model).unwrap();
    let local_payload = openai_chat_payload(&request, &local.model).unwrap();
    assert_eq!(
        remote_payload.get("messages"),
        local_payload.get("messages")
    );
    assert_eq!(remote_payload.get("tools"), local_payload.get("tools"));
    assert_ne!(remote_payload.get("model"), local_payload.get("model"));
}

#[test]
fn native_tool_history_renders_as_assistant_and_tool_messages() {
    let mut request = request();
    request.messages.extend([
        ModelMessage {
            role: ModelRole::Assistant,
            content: String::new(),
            name: None,
            tool_call_id: None,
            tool_calls: vec![ModelMessageToolCall {
                id: "call-1".to_owned(),
                name: "read_campaign_object".to_owned(),
                arguments: json!({"objectId": "observation-1"}),
            }],
        },
        ModelMessage {
            role: ModelRole::Tool,
            content: "{}".to_owned(),
            name: Some("read_campaign_object".to_owned()),
            tool_call_id: Some("call-1".to_owned()),
            tool_calls: vec![],
        },
    ]);
    let payload = openai_chat_payload(&request, "example").unwrap();
    assert_eq!(
        payload.pointer("/messages/1/role").and_then(Value::as_str),
        Some("assistant")
    );
    assert_eq!(
        payload.pointer("/messages/2/role").and_then(Value::as_str),
        Some("tool")
    );
}

#[test]
fn compatible_response_normalizes_text_tools_and_usage() {
    let payload = json!({
        "choices": [{
            "message": {
                "content": "I need the recorded object.",
                "tool_calls": [{
                    "id": "call-1",
                    "function": {
                        "name": "read_campaign_object",
                        "arguments": "{\"objectId\":\"observation-1\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
    });
    let response =
        normalize_openai_chat_response("request-1", "remote", "example", &payload).unwrap();
    assert_eq!(response.contract, MODEL_RESPONSE_CONTRACT);
    assert_eq!(response.output.len(), 2);
}

#[test]
fn malformed_tool_arguments_fail_closed() {
    let payload = json!({
        "choices": [{"message": {"tool_calls": [{
            "id": "call-1",
            "function": {"name": "read_campaign_object", "arguments": "not-json"}
        }]}}]
    });
    assert!(
        normalize_openai_chat_response("request-1", "remote", "example", &payload)
            .unwrap_err()
            .to_string()
            .contains("malformed JSON")
    );
}
