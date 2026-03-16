use crate::mcp::protocol::ToolCallResult;

struct BestPractice {
    topic: &'static str,
    content: &'static str,
}

static PRACTICES: &[BestPractice] = &[
    BestPractice {
        topic: "jwt-auth",
        content: include_str!("../../../knowledge/best-practices/jwt-auth.md"),
    },
    BestPractice {
        topic: "rls-policy",
        content: include_str!("../../../knowledge/best-practices/rls-policy.md"),
    },
    BestPractice {
        topic: "file-upload",
        content: include_str!("../../../knowledge/best-practices/file-upload.md"),
    },
    BestPractice {
        topic: "cors",
        content: include_str!("../../../knowledge/best-practices/cors.md"),
    },
    BestPractice {
        topic: "rate-limiting",
        content: include_str!("../../../knowledge/best-practices/rate-limiting.md"),
    },
    BestPractice {
        topic: "password-storage",
        content: include_str!("../../../knowledge/best-practices/password-storage.md"),
    },
    BestPractice {
        topic: "input-validation",
        content: include_str!("../../../knowledge/best-practices/input-validation.md"),
    },
    BestPractice {
        topic: "session-management",
        content: include_str!("../../../knowledge/best-practices/session-management.md"),
    },
    BestPractice {
        topic: "api-auth",
        content: include_str!("../../../knowledge/best-practices/api-auth.md"),
    },
    BestPractice {
        topic: "error-handling",
        content: include_str!("../../../knowledge/best-practices/error-handling.md"),
    },
    BestPractice {
        topic: "database-security",
        content: include_str!("../../../knowledge/best-practices/database-security.md"),
    },
    BestPractice {
        topic: "docker-security",
        content: include_str!("../../../knowledge/best-practices/docker-security.md"),
    },
    BestPractice {
        topic: "oauth-security",
        content: include_str!("../../../knowledge/best-practices/oauth-security.md"),
    },
    BestPractice {
        topic: "websocket-security",
        content: include_str!("../../../knowledge/best-practices/websocket-security.md"),
    },
    BestPractice {
        topic: "logging-security",
        content: include_str!("../../../knowledge/best-practices/logging-security.md"),
    },
    BestPractice {
        topic: "dependency-management",
        content: include_str!("../../../knowledge/best-practices/dependency-management.md"),
    },
    BestPractice {
        topic: "secrets-management",
        content: include_str!("../../../knowledge/best-practices/secrets-management.md"),
    },
];

pub fn best_practice(topic: &str) -> ToolCallResult {
    let normalized = topic.trim().to_lowercase();

    if let Some(practice) = PRACTICES.iter().find(|p| p.topic == normalized) {
        return super::text_result(practice.content);
    }

    let available: Vec<&str> = PRACTICES.iter().map(|p| p.topic).collect();
    super::error_result(&format!(
        "Unknown topic '{}'. Available topics: {}",
        topic,
        available.join(", ")
    ))
}
