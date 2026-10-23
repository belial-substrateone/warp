//! Canned agent response for AnonWarp's offline mode.
//!
//! With the Warp server stubbed out there is no LLM behind `/ai/multi-agent`, so instead of
//! failing the request this synthesizes the event sequence the server would send for a
//! one-message reply: stream init, the reply message added to the conversation's root task
//! (created if this is a new conversation), and a graceful finish. The real local backend
//! replaces `placeholder_events`.

use api::response_event::stream_finished::{Done, Reason};
use warp_multi_agent_api as api;

const PLACEHOLDER_TEXT: &str = "AI is not configured in AnonWarp yet. This client is running \
without the Warp server, so there is no model behind the agent. Terminal features work as normal.";

/// Events for a single placeholder reply to `request`.
pub fn placeholder_events(request: &api::Request) -> Vec<api::ResponseEvent> {
    let conversation_id = request
        .metadata
        .as_ref()
        .map(|m| m.conversation_id.clone())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let request_id = uuid::Uuid::new_v4().to_string();

    // The root task is the one without a parent.
    let existing_root = request.task_context.as_ref().and_then(|ctx| {
        ctx.tasks.iter().find(|task| {
            task.dependencies
                .as_ref()
                .is_none_or(|deps| deps.parent_task_id.is_empty())
        })
    });
    let task_id = existing_root
        .map(|task| task.id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let now = chrono::Utc::now();
    let message = api::Message {
        id: uuid::Uuid::new_v4().to_string(),
        task_id: task_id.clone(),
        request_id: request_id.clone(),
        timestamp: Some(prost_types::Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        }),
        message: Some(api::message::Message::AgentOutput(
            api::message::AgentOutput {
                text: PLACEHOLDER_TEXT.to_owned(),
            },
        )),
        ..Default::default()
    };

    let action = if existing_root.is_some() {
        api::client_action::Action::AddMessagesToTask(api::client_action::AddMessagesToTask {
            task_id,
            messages: vec![message],
        })
    } else {
        api::client_action::Action::CreateTask(api::client_action::CreateTask {
            task: Some(api::Task {
                id: task_id,
                messages: vec![message],
                ..Default::default()
            }),
        })
    };

    vec![
        api::ResponseEvent {
            r#type: Some(api::response_event::Type::Init(
                api::response_event::StreamInit {
                    conversation_id,
                    request_id,
                    run_id: uuid::Uuid::new_v4().to_string(),
                },
            )),
        },
        api::ResponseEvent {
            r#type: Some(api::response_event::Type::ClientActions(
                api::response_event::ClientActions {
                    actions: vec![api::ClientAction {
                        action: Some(action),
                    }],
                },
            )),
        },
        api::ResponseEvent {
            r#type: Some(api::response_event::Type::Finished(
                api::response_event::StreamFinished {
                    reason: Some(Reason::Done(Done::default())),
                    ..Default::default()
                },
            )),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(events: &[api::ResponseEvent]) -> Vec<&'static str> {
        events
            .iter()
            .map(|e| match e.r#type {
                Some(api::response_event::Type::Init(_)) => "init",
                Some(api::response_event::Type::ClientActions(_)) => "actions",
                Some(api::response_event::Type::Finished(_)) => "finished",
                None => "none",
            })
            .collect()
    }

    #[test]
    fn new_conversation_creates_root_task() {
        let events = placeholder_events(&api::Request::default());
        assert_eq!(kinds(&events), ["init", "actions", "finished"]);
        let Some(api::response_event::Type::ClientActions(actions)) = &events[1].r#type else {
            panic!("expected client actions");
        };
        assert!(matches!(
            actions.actions[0].action,
            Some(api::client_action::Action::CreateTask(_))
        ));
    }

    #[test]
    fn existing_root_task_gets_message_appended() {
        let request = api::Request {
            task_context: Some(api::request::TaskContext {
                tasks: vec![api::Task {
                    id: "root".to_owned(),
                    ..Default::default()
                }],
            }),
            ..Default::default()
        };
        let events = placeholder_events(&request);
        let Some(api::response_event::Type::ClientActions(actions)) = &events[1].r#type else {
            panic!("expected client actions");
        };
        let Some(api::client_action::Action::AddMessagesToTask(add)) = &actions.actions[0].action
        else {
            panic!("expected AddMessagesToTask");
        };
        assert_eq!(add.task_id, "root");
    }
}
