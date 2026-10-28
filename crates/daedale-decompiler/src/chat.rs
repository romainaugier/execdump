// SPDX-License-Identifier: Apache-2.0
/*
 * Clients of the LLM APIs, in three formats: OpenAI chat completions (OpenAI, DeepSeek, Mistral, Groq, xAI,
 * OpenRouter, Ollama and any compatible server), Anthropic messages and Google Gemini.
 *
 * Every backend works the same way: the answer is streamed (the timeout is the longest silence allowed, a
 * long answer is never cut by it), max_tokens is sent, a JSON object following a schema is asked for (with
 * the API's own structured output when it has one, the schema is in the system prompt anyway), an answer cut
 * by max_tokens is an error, and the errors give the HTTP status with what the API answered.
 */

use super::llm::LlmConfig;

use anyhow::{anyhow, bail, Context, Result};

use serde_json::{json, Value};

use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Format {
    /// Chat completions, with the JSON schema response format or the JSON object one
    OpenAi { json_schema: bool, completion_tokens: bool },
    Anthropic,
    Google,
}

pub(crate) struct Chat {
    client: reqwest::Client,
    format: Format,
    url: String,
    headers: Vec<(&'static str, String)>,
    model: String,
    system: String,
    name: String,
    schema: Value,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Default)]
struct Answer {
    text: String,
    cut: bool,
    reason: Option<String>,
}

impl Answer {
    /// Why the model stopped, cut when it is the reason for max_tokens
    fn stop(&mut self, reason: &Value, cut: &str) {
        if let Some(reason) = reason.as_str() {
            self.cut |= reason == cut;
            self.reason = Some(reason.to_string());
        }
    }
}

pub(crate) const BACKENDS: &str = "openai, anthropic, google, deepseek, mistral, groq, xai, openrouter, ollama, openai-compatible";

/// Base URL of an API without its version path, which the endpoint path has
fn base<'a>(config: &'a LlmConfig, default: &'a str, version: &str) -> String {
    let base = config.base_url.as_deref().unwrap_or(default).trim_end_matches('/');
    return base.strip_suffix(version).unwrap_or(base).to_string();
}

impl Chat {
    pub fn new(config: &LlmConfig, system: &str, name: &str, schema: Value, max_tokens: u32) -> Result<Chat> {
        let openai = |json_schema| Format::OpenAi { json_schema, completion_tokens: false };

        let (format, base_url) = match config.backend.as_str() {
            "openai" => (Format::OpenAi { json_schema: true, completion_tokens: true }, Some("https://api.openai.com/v1")),
            "deepseek" => (openai(false), Some("https://api.deepseek.com/v1")),
            "mistral" => (openai(true), Some("https://api.mistral.ai/v1")),
            "groq" => (openai(false), Some("https://api.groq.com/openai/v1")),
            "xai" => (openai(true), Some("https://api.x.ai/v1")),
            "openrouter" => (openai(true), Some("https://openrouter.ai/api/v1")),
            "ollama" => (openai(true), Some("http://localhost:11434/v1")),
            "openai-compatible" => (openai(false), None),
            "anthropic" => (Format::Anthropic, Some("https://api.anthropic.com/v1")),
            "google" | "gemini" => (Format::Google, Some("https://generativelanguage.googleapis.com/v1beta")),
            other => bail!("unknown backend {}: {}", other, BACKENDS),
        };

        let url = match (format, base_url) {
            (Format::OpenAi { .. }, None) => {
                let base = config.base_url.as_deref().context("the openai-compatible backend needs a base_url")?;
                format!("{}/chat/completions", base.trim_end_matches('/'))
            }
            (Format::OpenAi { .. }, Some(default)) => format!("{}/v1/chat/completions", base(config, default, "/v1")),
            (Format::Anthropic, default) => format!("{}/v1/messages", base(config, default.unwrap_or_default(), "/v1")),
            (Format::Google, default) => {
                let model = config.model.strip_prefix("models/").unwrap_or(&config.model);
                format!("{}/v1beta/models/{}:streamGenerateContent?alt=sse", base(config, default.unwrap_or_default(), "/v1beta"), model)
            }
        };

        let key = match (&config.api_key, &config.api_key_env) {
            (Some(key), _) => Some(key.clone()),
            (None, Some(variable)) => Some(std::env::var(variable).map_err(|_| anyhow!("the environment variable {} of the API key is not set", variable))?),
            (None, None) => None,
        };

        let local = matches!(config.backend.as_str(), "ollama" | "openai-compatible");

        let headers = match (format, key) {
            (_, None) if !local => bail!("the {} backend needs an api_key or api_key_env in the [llm] section", config.backend),
            (_, None) => Vec::new(),
            (Format::OpenAi { .. }, Some(key)) => vec![("authorization", format!("Bearer {}", key))],
            (Format::Anthropic, Some(key)) => vec![("x-api-key", key), ("anthropic-version", "2023-06-01".to_string())],
            (Format::Google, Some(key)) => vec![("x-goog-api-key", key)],
        };

        let timeout = Duration::from_secs(config.timeout.max(1));
        let client = reqwest::Client::builder().connect_timeout(timeout).read_timeout(timeout).build()?;

        return Ok(Chat {
            client,
            format,
            url,
            headers,
            model: config.model.clone(),
            system: format!("{}\n\nThe JSON object follows this JSON schema:\n{}", system, schema),
            name: name.to_string(),
            schema,
            max_tokens,
            temperature: config.temperature,
        });
    }

    fn body(&self, prompt: &str, temperature: bool) -> Value {
        let mut body = match self.format {
            Format::OpenAi { json_schema, completion_tokens } => {
                let response_format = if json_schema {
                    json!({ "type": "json_schema", "json_schema": { "name": self.name, "schema": self.schema, "strict": true } })
                } else {
                    json!({ "type": "json_object" })
                };

                let mut body = json!({
                    "model": self.model,
                    "messages": [{ "role": "system", "content": self.system }, { "role": "user", "content": prompt }],
                    "response_format": response_format,
                    "stream": true,
                });

                body[if completion_tokens { "max_completion_tokens" } else { "max_tokens" }] = json!(self.max_tokens);
                body
            }
            // The answer is the input of a tool the model has to call
            Format::Anthropic => json!({
                "model": self.model,
                "max_tokens": self.max_tokens,
                "system": self.system,
                "messages": [{ "role": "user", "content": prompt }],
                "tools": [{ "name": self.name, "description": "Gives the answer", "input_schema": self.schema }],
                "tool_choice": { "type": "tool", "name": self.name },
                "stream": true,
            }),
            // Its response schema refuses parts of JSON schema (additionalProperties): the prompt has it
            Format::Google => json!({
                "systemInstruction": { "parts": [{ "text": self.system }] },
                "contents": [{ "role": "user", "parts": [{ "text": prompt }] }],
                "generationConfig": { "maxOutputTokens": self.max_tokens, "responseMimeType": "application/json" },
            }),
        };

        if temperature {
            let fields = if self.format == Format::Google { &mut body["generationConfig"] } else { &mut body };
            fields["temperature"] = json!(self.temperature);
        }

        return body;
    }

    pub async fn ask(&self, prompt: &str) -> Result<String> {
        let mut temperature = true;

        let response = loop {
            let mut request = self.client.post(&self.url).json(&self.body(prompt, temperature));

            for (name, value) in self.headers.iter() {
                request = request.header(*name, value);
            }

            let response = request.send().await.map_err(|e| anyhow!(describe(&e)))?;
            let status = response.status();

            if status.is_success() {
                break response;
            }

            let text = response.text().await.unwrap_or_default();

            // Reasoning models only take their own temperature
            if temperature && status.as_u16() == 400 && text.contains("temperature") {
                temperature = false;
                continue;
            }

            let message = serde_json::from_str::<Value>(&text).ok().and_then(|v| v.get("error").map(error_text)).unwrap_or_else(|| text.trim().to_string());
            bail!("{} answered {}: {}", self.url.split('?').next().unwrap_or(&self.url), status, message);
        };

        let answer = self.read(response).await?;

        if answer.cut {
            bail!("the answer was cut at {} tokens, raise max_tokens in the [llm] section", self.max_tokens);
        }

        if answer.text.trim().is_empty() {
            return Err(match answer.reason {
                Some(reason) => anyhow!("empty answer (stopped: {})", reason),
                None => anyhow!("empty answer"),
            });
        }

        return Ok(answer.text);
    }

    /// Server sent events ("data: {event}" lines), or one JSON answer from servers that do not stream
    async fn read(&self, mut response: reqwest::Response) -> Result<Answer> {
        let (mut pending, mut whole, mut events) = (String::new(), String::new(), 0);
        let mut answer = Answer::default();

        while let Some(bytes) = response.chunk().await.map_err(|e| anyhow!(describe(&e)))? {
            pending.push_str(&String::from_utf8_lossy(&bytes));

            while let Some(end) = pending.find('\n') {
                let line: String = pending.drain(..=end).collect();

                let Some(data) = line.trim().strip_prefix("data:").map(str::trim) else {
                    if events == 0 {
                        whole.push_str(&line);
                    }

                    continue;
                };

                events += 1;

                if data == "[DONE]" {
                    return Ok(answer);
                }

                let event: Value = serde_json::from_str(data).map_err(|e| anyhow!("unexpected answer ({}): {}", e, data))?;
                self.event(&event, &mut answer)?;
            }
        }

        if events == 0 {
            whole.push_str(&pending);
            let event: Value = serde_json::from_str(&whole).map_err(|e| anyhow!("unexpected answer ({}): {}", e, whole.trim()))?;
            self.event(&event, &mut answer)?;
        }

        return Ok(answer);
    }

    fn event(&self, event: &Value, answer: &mut Answer) -> Result<()> {
        if let Some(error) = event.get("error") {
            bail!("the API answered: {}", error_text(error));
        }

        match self.format {
            Format::OpenAi { .. } => {
                for choice in event["choices"].as_array().into_iter().flatten() {
                    answer.stop(&choice["finish_reason"], "length");

                    // Streamed (delta) or whole (message)
                    let content = choice["delta"]["content"].as_str().or(choice["message"]["content"].as_str());
                    answer.text.push_str(content.unwrap_or(""));
                }
            }
            Format::Anthropic => match event["type"].as_str().unwrap_or("") {
                "content_block_delta" => {
                    let delta = &event["delta"];
                    answer.text.push_str(delta["partial_json"].as_str().or(delta["text"].as_str()).unwrap_or(""));
                }
                "message_delta" => answer.stop(&event["delta"]["stop_reason"], "max_tokens"),
                "message" => {
                    answer.stop(&event["stop_reason"], "max_tokens");

                    for block in event["content"].as_array().into_iter().flatten() {
                        match block["type"].as_str() {
                            Some("tool_use") => answer.text.push_str(&block["input"].to_string()),
                            _ => answer.text.push_str(block["text"].as_str().unwrap_or("")),
                        }
                    }
                }
                _ => {}
            },
            Format::Google => {
                // A whole answer is the list of the streamed events
                if let Some(events) = event.as_array() {
                    return events.iter().try_for_each(|e| self.event(e, answer));
                }

                if let Some(reason) = event["promptFeedback"]["blockReason"].as_str() {
                    bail!("the prompt was blocked: {}", reason);
                }

                let candidate = &event["candidates"][0];
                answer.stop(&candidate["finishReason"], "MAX_TOKENS");

                for part in candidate["content"]["parts"].as_array().into_iter().flatten().filter(|p| p["thought"] != json!(true)) {
                    answer.text.push_str(part["text"].as_str().unwrap_or(""));
                }
            }
        }

        return Ok(());
    }
}

/// Message of the error object of an API (a string, or an object with a message)
fn error_text(error: &Value) -> String {
    if let Some(text) = error.as_str() {
        return text.to_string();
    }

    let message = error["message"].as_str().map(str::to_string).unwrap_or_else(|| error.to_string());

    return match error["type"].as_str().or(error["status"].as_str()) {
        Some(kind) => format!("{} ({})", message, kind),
        None => message,
    };
}

/// An HTTP error with its causes (reqwest says "error decoding response body" for a timeout)
fn describe(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);

    while let Some(cause) = source {
        text.push_str(&format!(": {}", cause));
        source = cause.source();
    }

    if error.is_timeout() {
        text.push_str(" (the timeout of the [llm] section is the longest silence allowed)");
    }

    return text;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::mpsc::Receiver;

    /// Answers one request with a status and a body (an API on the loopback), gives the request
    pub(crate) fn serve(status: &'static str, body: String) -> (String, Receiver<String>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, receiver) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];

            // Headers, then the JSON body of the request (its content length)
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request).to_lowercase();

                if let Some(end) = text.find("\r\n\r\n") {
                    let length: usize = text.split("content-length:").nth(1).and_then(|l| l.lines().next()).and_then(|l| l.trim().parse().ok()).unwrap_or(0);

                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }

            let response = format!("HTTP/1.1 {}\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", status, body.len(), body);
            stream.write_all(response.as_bytes()).unwrap();
            sender.send(String::from_utf8_lossy(&request).to_string()).unwrap();
        });

        return (url, receiver);
    }

    fn config(backend: &str, url: String) -> LlmConfig {
        return LlmConfig { backend: backend.to_string(), model: "test".to_string(), api_key: Some("secret".to_string()), base_url: Some(url), timeout: 10, ..Default::default() };
    }

    fn chat(backend: &str, url: String) -> Chat {
        return Chat::new(&config(backend, url), "Answer.", "answer", json!({ "type": "object" }), 100).unwrap();
    }

    fn ask(chat: &Chat) -> Result<String> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        return runtime.block_on(chat.ask("question"));
    }

    fn events(events: &[Value]) -> String {
        return events.iter().map(|e| format!("data: {}\n\n", e)).collect();
    }

    const ANSWER: &str = "{\"code\": \"int f(void) { return 1; }\"}";

    #[test]
    fn openai_format() {
        let (first, second) = ANSWER.split_at(10);
        let chunk = |text: &str, finish: Option<&str>| json!({ "choices": [{ "delta": { "content": text }, "finish_reason": finish }] });

        let (url, request) = serve("200 OK", events(&[chunk(first, None), chunk(second, Some("stop"))]) + "data: [DONE]\n\n");
        assert_eq!(ask(&chat("openai", url)).unwrap(), ANSWER);

        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /v1/chat/completions") && request.contains("Bearer secret"), "{}", request);
        assert!(request.contains("\"max_completion_tokens\":100") && request.contains("\"json_schema\"") && request.contains("\"stream\":true"), "{}", request);

        // Compatible servers: their base_url as given, the JSON object mode
        let (url, request) = serve("200 OK", events(&[chunk(ANSWER, Some("stop"))]));
        assert_eq!(ask(&chat("openai-compatible", format!("{}/api", url))).unwrap(), ANSWER);

        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /api/chat/completions") && request.contains("\"max_tokens\":100") && request.contains("json_object"), "{}", request);

        // What the API says is the error
        let (url, _) = serve("402 Payment Required", "{\"error\":\"Insufficient Balance\"}".to_string());
        let error = ask(&chat("deepseek", url)).unwrap_err().to_string();
        assert!(error.contains("402") && error.contains("Insufficient Balance"), "{}", error);

        let (url, _) = serve("200 OK", events(&[json!({ "error": { "message": "overloaded" } })]));
        assert!(ask(&chat("openrouter", url)).unwrap_err().to_string().contains("overloaded"));

        // Cut answers
        let (url, _) = serve("200 OK", events(&[chunk("{\"code\": \"int", Some("length"))]));
        assert!(ask(&chat("mistral", url)).unwrap_err().to_string().contains("max_tokens"));

        // Servers that do not stream
        let (url, _) = serve("200 OK", json!({ "choices": [{ "message": { "content": ANSWER }, "finish_reason": "stop" }] }).to_string());
        assert_eq!(ask(&chat("ollama", url)).unwrap(), ANSWER);
    }

    #[test]
    fn anthropic_format() {
        let delta = |json: &str| json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "input_json_delta", "partial_json": json } });
        let (first, second) = ANSWER.split_at(7);

        let body = format!(
            "event: message_start\n{}event: content_block_delta\n{}",
            events(&[json!({ "type": "message_start", "message": {} }), json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "tool_use", "input": {} } })]),
            events(&[delta(first), delta(second), json!({ "type": "message_delta", "delta": { "stop_reason": "tool_use" } }), json!({ "type": "message_stop" })])
        );

        let (url, request) = serve("200 OK", body);
        assert_eq!(ask(&chat("anthropic", url)).unwrap(), ANSWER);

        let request = request.recv().unwrap().to_lowercase();
        assert!(request.starts_with("post /v1/messages") && request.contains("x-api-key: secret") && request.contains("anthropic-version"), "{}", request);
        assert!(request.contains("\"tool_choice\"") && request.contains("\"type\":\"tool\"") && request.contains("\"max_tokens\":100"), "{}", request);

        let (url, _) = serve("200 OK", events(&[delta("{\"co"), json!({ "type": "message_delta", "delta": { "stop_reason": "max_tokens" } })]));
        assert!(ask(&chat("anthropic", url)).unwrap_err().to_string().contains("max_tokens"));

        let (url, _) = serve("200 OK", events(&[json!({ "type": "error", "error": { "type": "overloaded_error", "message": "Overloaded" } })]));
        assert!(ask(&chat("anthropic", url)).unwrap_err().to_string().contains("Overloaded"));

        let (url, _) = serve("401 Unauthorized", json!({ "type": "error", "error": { "type": "authentication_error", "message": "invalid x-api-key" } }).to_string());
        let error = ask(&chat("anthropic", url)).unwrap_err().to_string();
        assert!(error.contains("401") && error.contains("invalid x-api-key"), "{}", error);
    }

    #[test]
    fn google_format() {
        let part = |text: &str, finish: Option<&str>| json!({ "candidates": [{ "content": { "role": "model", "parts": [{ "text": text }] }, "finishReason": finish }] });
        let (first, second) = ANSWER.split_at(12);

        let (url, request) = serve("200 OK", events(&[part(first, None), part(second, Some("STOP"))]));
        assert_eq!(ask(&chat("google", format!("{}/v1beta", url))).unwrap(), ANSWER);

        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /v1beta/models/test:streamGenerateContent?alt=sse") && request.contains("x-goog-api-key: secret"), "{}", request);
        assert!(request.contains("\"maxOutputTokens\":100") && request.contains("application/json") && request.contains("\"temperature\""), "{}", request);

        let (url, _) = serve("200 OK", events(&[part("{\"code", Some("MAX_TOKENS"))]));
        assert!(ask(&chat("google", url)).unwrap_err().to_string().contains("max_tokens"));

        let (url, _) = serve("200 OK", events(&[part("", Some("SAFETY"))]));
        assert!(ask(&chat("google", url)).unwrap_err().to_string().contains("SAFETY"));
    }

    #[test]
    fn configurations() {
        let error = |config: LlmConfig| Chat::new(&config, "", "answer", json!({}), 100).err().unwrap().to_string();

        assert!(error(LlmConfig { backend: "claude".to_string(), ..config("anthropic", String::new()) }).contains("unknown backend claude"));
        assert!(error(LlmConfig { api_key: None, ..config("openai", String::new()) }).contains("api_key"));
        assert!(error(LlmConfig { api_key: None, api_key_env: Some("DAEDALE_NO_SUCH_KEY".to_string()), ..config("openai", String::new()) }).contains("DAEDALE_NO_SUCH_KEY"));
        assert!(error(LlmConfig { base_url: None, ..config("openai-compatible", String::new()) }).contains("base_url"));

        // Local servers need no key, the version of the base URL is optional
        let ollama = Chat::new(&LlmConfig { api_key: None, base_url: Some("http://host:11434".to_string()), ..config("ollama", String::new()) }, "", "answer", json!({}), 100).unwrap();
        assert_eq!(ollama.url, "http://host:11434/v1/chat/completions");

        let default = Chat::new(&LlmConfig { base_url: None, ..config("anthropic", String::new()) }, "", "answer", json!({}), 100).unwrap();
        assert_eq!(default.url, "https://api.anthropic.com/v1/messages");
    }
}
