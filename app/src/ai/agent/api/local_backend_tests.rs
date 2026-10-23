use std::io::{Read as _, Write as _};

use futures::StreamExt as _;

use super::*;

fn kinds(events: &[api::ResponseEvent]) -> Vec<&'static str> {
    events
        .iter()
        .map(|e| match &e.r#type {
            Some(api::response_event::Type::Init(_)) => "init",
            Some(api::response_event::Type::Finished(_)) => "finished",
            Some(api::response_event::Type::ClientActions(a)) => match a.actions[0].action {
                Some(api::client_action::Action::CreateTask(_)) => "create",
                Some(api::client_action::Action::AddMessagesToTask(_)) => "add",
                Some(api::client_action::Action::AppendToMessageContent(_)) => "append",
                _ => "other",
            },
            None => "none",
        })
        .collect()
}

fn user_query_request(text: &str) -> api::Request {
    api::Request {
        input: Some(api::request::Input {
            r#type: Some(api::request::input::Type::UserInputs(
                api::request::input::UserInputs {
                    inputs: vec![api::request::input::user_inputs::UserInput {
                        input: Some(
                            api::request::input::user_inputs::user_input::Input::UserQuery(
                                api::request::input::UserQuery {
                                    query: text.to_owned(),
                                    ..Default::default()
                                },
                            ),
                        ),
                    }],
                },
            )),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn collect(
    request: &api::Request,
    deltas: Vec<Result<String>>,
) -> Vec<api::ResponseEvent> {
    let meta = ReplyMeta::from_request(request);
    futures::executor::block_on(
        events_from_deltas(meta, "http://x/v1".to_owned(), futures::stream::iter(deltas))
            .collect::<Vec<_>>(),
    )
}

#[test]
fn history_includes_prior_turns_and_new_query() {
    let mut request = user_query_request("and now?");
    request.task_context = Some(api::request::TaskContext {
        tasks: vec![api::Task {
            id: "root".into(),
            messages: vec![
                api::Message {
                    message: Some(api::message::Message::UserQuery(api::message::UserQuery {
                        query: "hi".into(),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
                api::Message {
                    message: Some(api::message::Message::AgentOutput(
                        api::message::AgentOutput {
                            text: "hello".into(),
                        },
                    )),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
    });
    let history = build_chat_history(&request);
    let roles: Vec<_> = history.iter().map(|m| m.role.as_str()).collect();
    assert_eq!(roles, ["system", "user", "assistant", "user"]);
    assert_eq!(history[1].content, "hi");
    assert_eq!(history[3].content, "and now?");
}

#[test]
fn resume_conversation_appends_continue() {
    let request = api::Request {
        input: Some(api::request::Input {
            r#type: Some(api::request::input::Type::ResumeConversation(
                Default::default(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    };
    let history = build_chat_history(&request);
    assert_eq!(history.last().unwrap().content, "Continue.");
}

#[test]
fn system_prompt_includes_context() {
    let mut request = user_query_request("x");
    request.input.as_mut().unwrap().context = Some(api::InputContext {
        directory: Some(api::input_context::Directory {
            pwd: "/tmp/proj".into(),
            ..Default::default()
        }),
        shell: Some(api::input_context::Shell {
            name: "zsh".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    let system = &build_chat_history(&request)[0].content;
    assert!(system.contains("/tmp/proj") && system.contains("zsh"));
}

#[test]
fn new_conversation_streams_create_then_appends() {
    let events = collect(
        &user_query_request("q"),
        vec![Ok("Hel".into()), Ok("lo".into()), Ok("!".into())],
    );
    assert_eq!(
        kinds(&events),
        ["init", "create", "append", "append", "finished"]
    );
    let Some(api::response_event::Type::ClientActions(a)) = &events[3].r#type else {
        panic!()
    };
    let Some(api::client_action::Action::AppendToMessageContent(app)) = &a.actions[0].action
    else {
        panic!()
    };
    assert_eq!(app.mask.as_ref().unwrap().paths, ["agent_output.text"]);
    assert_eq!(app.task_id, app.message.as_ref().unwrap().task_id);
}

#[test]
fn existing_root_uses_add_messages() {
    let mut request = user_query_request("q");
    request.task_context = Some(api::request::TaskContext {
        tasks: vec![api::Task {
            id: "root".into(),
            ..Default::default()
        }],
    });
    let events = collect(&request, vec![Ok("a".into())]);
    assert_eq!(kinds(&events), ["init", "add", "finished"]);
}

#[test]
fn error_before_output_shows_message_and_llm_unavailable() {
    let events = collect(&user_query_request("q"), vec![Err(anyhow::anyhow!("refused"))]);
    assert_eq!(kinds(&events), ["init", "create", "finished"]);
    let Some(api::response_event::Type::Finished(f)) = &events[2].r#type else {
        panic!()
    };
    assert!(matches!(f.reason, Some(Reason::LlmUnavailable(_))));
    let Some(api::response_event::Type::ClientActions(a)) = &events[1].r#type else {
        panic!()
    };
    let Some(api::client_action::Action::CreateTask(c)) = &a.actions[0].action else {
        panic!()
    };
    let Some(api::message::Message::AgentOutput(o)) =
        &c.task.as_ref().unwrap().messages[0].message
    else {
        panic!()
    };
    assert!(o.text.contains("http://x/v1") && o.text.contains("refused"));
}

#[test]
fn empty_stream_still_finishes_with_visible_message() {
    let events = collect(&user_query_request("q"), vec![]);
    assert_eq!(kinds(&events), ["init", "create", "finished"]);
}

fn serve_sse(body: String) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            // Read headers and (small) body; the exact amount does not matter for the mock.
            let _ = stream.read(&mut buf);
            let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });
    format!("http://{addr}/v1")
}

#[test]
fn streams_from_mock_http_server() {
    let chunk = |t: &str| format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{t}\"}}}}]}}\n\n");
    let body = format!("{}{}data: [DONE]\n\n", chunk("Hi"), chunk(" there"));
    let config = LocalLlmConfig {
        base_url: serve_sse(body),
        model: "m".into(),
        api_key: None,
    };
    let events = futures::executor::block_on(
        local_agent_events_with_config(user_query_request("q"), config).collect::<Vec<_>>(),
    );
    let events: Vec<_> = events.into_iter().map(|e| e.unwrap()).collect();
    assert_eq!(kinds(&events), ["init", "create", "append", "finished"]);
}

#[test]
fn unreachable_server_reports_llm_unavailable() {
    // Bind then drop to get a port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = LocalLlmConfig {
        base_url: format!("http://127.0.0.1:{port}/v1"),
        model: "m".into(),
        api_key: None,
    };
    let events = futures::executor::block_on(
        local_agent_events_with_config(user_query_request("q"), config).collect::<Vec<_>>(),
    );
    let events: Vec<_> = events.into_iter().map(|e| e.unwrap()).collect();
    assert_eq!(kinds(&events), ["init", "create", "finished"]);
}
