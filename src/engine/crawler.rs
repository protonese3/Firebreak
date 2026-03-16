use crate::safety::Safety;
use regex::Regex;
use reqwest::Client;
use std::collections::HashSet;

const MAX_DEPTH: u8 = 3;
const MAX_PAGES: usize = 50;

const STATIC_EXTENSIONS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map",
];

const BINARY_CONTENT_TYPES: &[&str] = &[
    "image/", "font/", "video/", "audio/", "application/octet-stream",
    "application/zip", "application/pdf",
];

fn resolve_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    if href.starts_with('/') {
        let parsed = url::Url::parse(base).ok()?;
        return Some(format!("{}://{}{}", parsed.scheme(), parsed.host_str()?, href));
    }
    url::Url::parse(base).ok()?.join(href).ok().map(|u| u.to_string())
}

fn normalize_url(u: &str) -> String {
    let without_fragment = u.split('#').next().unwrap_or(u);
    without_fragment.trim_end_matches('/').to_string()
}

fn is_same_host(base: &str, candidate: &str) -> bool {
    let base_host = url::Url::parse(base).ok().and_then(|u| u.host_str().map(String::from));
    let cand_host = url::Url::parse(candidate).ok().and_then(|u| u.host_str().map(String::from));
    match (base_host, cand_host) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn is_static_asset(url: &str) -> bool {
    let lower = url.to_lowercase();
    let path = lower.split('?').next().unwrap_or(&lower);
    STATIC_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

fn is_js_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let path = lower.split('?').next().unwrap_or(&lower);
    path.ends_with(".js")
}

fn is_binary_content_type(content_type: &str) -> bool {
    let lower = content_type.to_lowercase();
    BINARY_CONTENT_TYPES.iter().any(|bt| lower.contains(bt))
}

fn extract_html_links(body: &str, base_url: &str) -> Vec<String> {
    let re = Regex::new(r#"(?:href|action|src)=["']([^"'#]+)["']"#).unwrap();
    re.captures_iter(body)
        .filter_map(|cap| {
            let href = cap.get(1)?.as_str();
            resolve_url(base_url, href)
        })
        .collect()
}

fn extract_js_endpoints(body: &str, base_url: &str) -> Vec<String> {
    let patterns = [
        r#"fetch\(["']([^"']+)["']"#,
        r#"axios\.\w+\(["']([^"']+)["']"#,
        r#"["'](/api/[^"'\s]+)["']"#,
        r#"["']((?:/[a-z][a-z0-9_-]+){1,5})["']"#,
    ];

    let mut urls = Vec::new();
    for pat in &patterns {
        let re = match Regex::new(pat) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for cap in re.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let endpoint = m.as_str();
                if let Some(resolved) = resolve_url(base_url, endpoint) {
                    urls.push(resolved);
                }
            }
        }
    }
    urls
}

fn parse_sitemap_urls(body: &str) -> Vec<String> {
    let re = Regex::new(r"<loc>\s*([^<]+)\s*</loc>").unwrap();
    re.captures_iter(body)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().trim().to_string()))
        .collect()
}

fn parse_robots_paths(body: &str, base_url: &str) -> Vec<String> {
    let re = Regex::new(r"(?:Allow|Disallow|Sitemap):\s*(\S+)").unwrap();
    re.captures_iter(body)
        .filter_map(|cap| {
            let path = cap.get(1)?.as_str();
            resolve_url(base_url, path)
        })
        .collect()
}

async fn fetch_text(client: &Client, url: &str, safety: &Safety) -> Option<String> {
    if !safety.check_scope(url) {
        return None;
    }
    safety.acquire_rate_limit().await;
    safety.log_action("crawl", url, "Discovering endpoints");

    let resp = client.get(url).send().await.ok()?;
    let ct = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if is_binary_content_type(&ct) {
        return None;
    }

    resp.text().await.ok()
}

pub async fn crawl(client: &Client, target: &str, safety: &Safety) -> Vec<String> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut discovered: HashSet<String> = HashSet::new();
    let mut queue: Vec<(String, u8)> = vec![(normalize_url(target), 0)];
    let mut js_urls: Vec<String> = Vec::new();

    while let Some((url, depth)) = queue.pop() {
        if visited.len() >= MAX_PAGES {
            break;
        }
        let normalized = normalize_url(&url);
        if visited.contains(&normalized) {
            continue;
        }
        if !is_same_host(target, &normalized) {
            continue;
        }
        visited.insert(normalized.clone());
        discovered.insert(normalized.clone());

        let body = match fetch_text(client, &normalized, safety).await {
            Some(b) => b,
            None => continue,
        };

        let links = extract_html_links(&body, &normalized);
        for link in links {
            let norm = normalize_url(&link);
            if !is_same_host(target, &norm) {
                continue;
            }
            if is_js_url(&norm) {
                js_urls.push(norm.clone());
            }
            if is_static_asset(&norm) {
                continue;
            }
            discovered.insert(norm.clone());
            if depth < MAX_DEPTH && !visited.contains(&norm) {
                queue.push((norm, depth + 1));
            }
        }
    }

    let base = normalize_url(target);

    let sitemap_url = format!("{}/sitemap.xml", base);
    if let Some(body) = fetch_text(client, &sitemap_url, safety).await {
        for u in parse_sitemap_urls(&body) {
            let norm = normalize_url(&u);
            if is_same_host(target, &norm) && !is_static_asset(&norm) {
                discovered.insert(norm);
            }
        }
    }

    let robots_url = format!("{}/robots.txt", base);
    if let Some(body) = fetch_text(client, &robots_url, safety).await {
        for u in parse_robots_paths(&body, target) {
            let norm = normalize_url(&u);
            if is_same_host(target, &norm) && !is_static_asset(&norm) {
                discovered.insert(norm);
            }
        }
    }

    let mut js_visited: HashSet<String> = HashSet::new();
    for js_url in &js_urls {
        if js_visited.contains(js_url) {
            continue;
        }
        js_visited.insert(js_url.clone());
        let body = match fetch_text(client, js_url, safety).await {
            Some(b) => b,
            None => continue,
        };
        for endpoint in extract_js_endpoints(&body, target) {
            let norm = normalize_url(&endpoint);
            if is_same_host(target, &norm) && !is_static_asset(&norm) {
                discovered.insert(norm);
            }
        }
    }

    let mut result: Vec<String> = discovered.into_iter().collect();
    result.sort();
    result
}
