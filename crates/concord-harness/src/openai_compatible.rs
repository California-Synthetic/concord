use concord_protocol::{
    ModelExecutionRequest, ModelExecutionResponse, ModelOutputBlock, ModelRole, ModelUsage,
    MODEL_RESPONSE_CONTRACT,
};
use serde_json::{json, Value};
use thiserror::Error;

/// Render an OpenAI-compatible transport envelope from a canonical model request.
///
/// Provider identity, credentials, and routing rationale are deliberately excluded from the
/// canonical scientific request and supplied by the caller at the transport boundary.
pub fn openai_chat_payload(
    request: &ModelExecutionRequest,
    model: &str,
) -> Result<Value, OpenAiCompatibleError> {
    request.validate()?;
    if model.trim().is_empty() {
        return Err(OpenAiCompatibleError::MissingModel);
    }
    let messages = request
        .messages
        .iter()
        .map(|message| {
            let mut value = json!({
                "role": match message.role {
                    ModelRole::System => "system",
                    ModelRole::User => "user",
                    ModelRole::Assistant => "assistant",
                    ModelRole::Tool => "tool",
                },
                "content": message.content,
            });
            if let Some(name) = message.name.as_deref() {
                value["name"] = json!(name);
            }
            if let Some(tool_call_id) = message.tool_call_id.as_deref() {
                value["tool_call_id"] = json!(tool_call_id);
            }
            if !message.tool_calls.is_empty() {
                value["tool_calls"] = Value::Array(
                    message
                        .tool_calls
                        .iter()
                        .map(|call| {
                            json!({
                                "id": call.id,
                                "type": "function",
                                "function": {
                                    "name": call.name,
                                    "arguments": serde_json::to_string(&call.arguments)
                                        .expect("JSON value serialization cannot fail"),
                                }
                            })
                        })
                        .collect(),
                );
            }
            value
        })
        .collect::<Vec<_>>();
    let mut payload = json!({
        "model": model,
        "messages": messages,
        "max_tokens": request.limits.max_output_tokens,
    });
    if !request.tools.is_empty() {
        payload["tools"] = Value::Array(
            request
                .tools
                .iter()
                .map(|tool| {
                    json!({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.input_schema,
                        }
                    })
                })
                .collect(),
        );
    }
    if let Some(schema) = request.response_schema.as_ref() {
        payload["response_format"] = json!({
            "type": "json_schema",
            "json_schema": {"name": "concord_response", "strict": true, "schema": schema}
        });
    }
    Ok(payload)
}

/// Normalize an OpenAI-compatible provider response into the canonical response contract.
pub fn normalize_openai_chat_response(
    request_id: &str,
    provider_id: &str,
    model: &str,
    payload: &Value,
) -> Result<ModelExecutionResponse, OpenAiCompatibleError> {
    let message = payload
        .pointer("/choices/0/message")
        .ok_or(OpenAiCompatibleError::MissingMessage)?;
    let mut output = Vec::new();
    if let Some(content) = message.get("content") {
        if let Some(text) = content.as_str().filter(|value| !value.is_empty()) {
            output.push(ModelOutputBlock::Text {
                text: text.to_owned(),
            });
        } else if let Some(parts) = content.as_array() {
            for part in parts {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    output.push(ModelOutputBlock::Text {
                        text: text.to_owned(),
                    });
                }
            }
        }
    }
    if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
        for tool_call in tool_calls {
            let id = tool_call
                .get("id")
                .and_then(Value::as_str)
                .ok_or(OpenAiCompatibleError::MissingToolCallId)?;
            let name = tool_call
                .pointer("/function/name")
                .and_then(Value::as_str)
                .ok_or(OpenAiCompatibleError::MissingToolName)?;
            let raw_arguments = tool_call
                .pointer("/function/arguments")
                .and_then(Value::as_str)
                .ok_or(OpenAiCompatibleError::MissingToolArguments)?;
            let arguments = serde_json::from_str(raw_arguments).map_err(|source| {
                OpenAiCompatibleError::MalformedToolArguments {
                    id: id.to_owned(),
                    source,
                }
            })?;
            output.push(ModelOutputBlock::ToolCall {
                id: id.to_owned(),
                name: name.to_owned(),
                arguments,
            });
        }
    }
    let response = ModelExecutionResponse {
        contract: MODEL_RESPONSE_CONTRACT.to_owned(),
        request_id: request_id.to_owned(),
        provider_id: provider_id.to_owned(),
        model: model.to_owned(),
        output,
        finish_reason: payload
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        usage: ModelUsage {
            input_tokens: payload
                .pointer("/usage/prompt_tokens")
                .and_then(Value::as_u64),
            output_tokens: payload
                .pointer("/usage/completion_tokens")
                .and_then(Value::as_u64),
            total_tokens: payload
                .pointer("/usage/total_tokens")
                .and_then(Value::as_u64),
        },
    };
    response.validate()?;
    Ok(response)
}

#[derive(Debug, Error)]
pub enum OpenAiCompatibleError {
    #[error(transparent)]
    Contract(#[from] concord_protocol::ModelContractError),
    #[error("model is required")]
    MissingModel,
    #[error("compatible response is missing choices[0].message")]
    MissingMessage,
    #[error("tool call is missing id")]
    MissingToolCallId,
    #[error("tool call is missing function name")]
    MissingToolName,
    #[error("tool call is missing function arguments")]
    MissingToolArguments,
    #[error("tool call {id} contains malformed JSON arguments: {source}")]
    MalformedToolArguments {
        id: String,
        source: serde_json::Error,
    },
}
