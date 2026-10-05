//! Large tool results retain a bounded, short-lived report. The first reply says
//! it is truncated and provides a report ID; research_read returns exact chunks.

use crate::error::{ErrorCode, Result};
use crate::policy::sha256;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

struct Report {
    owner: u32,
    job: Option<Uuid>,
    text: Arc<String>,
    expires: Instant,
    serial: u64,
}
struct State {
    reports: HashMap<Uuid, Report>,
    bytes: usize,
    serial: u64,
}
pub struct Reports {
    state: Mutex<State>,
    maximum: usize,
    seconds: u64,
}

pub use crate::protocol::ReportChunk;

impl Reports {
    pub fn new(maximum: usize, seconds: u64) -> Self {
        Self {
            state: Mutex::new(State {
                reports: HashMap::new(),
                bytes: 0,
                serial: 0,
            }),
            maximum,
            seconds,
        }
    }

    pub fn bound(&self, owner: u32, job: Option<Uuid>, value: Value, cap: usize) -> Result<Value> {
        let text = serde_json::to_string(&value).map_err(|_| ErrorCode::InvalidResponse)?;
        if text.len() <= cap {
            return Ok(value);
        }
        if text.len() > self.maximum {
            return Err(ErrorCode::SizeLimit);
        }
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        prune(&mut state);
        while state.bytes + text.len() > self.maximum || state.reports.len() >= 128 {
            let oldest = state
                .reports
                .iter()
                .min_by_key(|(_, r)| r.serial)
                .map(|(id, _)| *id)
                .ok_or(ErrorCode::Storage)?;
            if let Some(removed) = state.reports.remove(&oldest) {
                state.bytes -= removed.text.len();
            }
        }
        let id = Uuid::new_v4();
        state.serial = state.serial.wrapping_add(1);
        let serial = state.serial;
        state.bytes += text.len();
        let bytes = text.len();
        state.reports.insert(
            id,
            Report {
                owner,
                job,
                text: Arc::new(text),
                expires: Instant::now() + Duration::from_secs(self.seconds),
                serial,
            },
        );
        let summary = json!({"truncated":true,"report_id":id,"report_bytes":bytes,"encoding":"json","untrusted":true,
            "coverage":value.get("coverage"),"usage":value.get("usage"),
            "continuation":{"tool":"research_read","arguments":{"kind":"report","report_id":id,"start":0}}});
        if serde_json::to_vec(&summary)
            .map_err(|_| ErrorCode::InvalidResponse)?
            .len()
            > cap
        {
            return Err(ErrorCode::SizeLimit);
        }
        Ok(summary)
    }

    pub fn read(&self, owner: u32, id: Uuid, start: u64, cap: usize) -> Result<ReportChunk> {
        if !(16..=262_144).contains(&cap) {
            return Err(ErrorCode::InvalidRequest);
        }
        let text = {
            let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            prune(&mut state);
            let report = state
                .reports
                .get(&id)
                .filter(|r| r.owner == owner)
                .ok_or(ErrorCode::SourceExpired)?;
            report.text.clone()
        };
        let total = text.chars().count() as u64;
        if start > total {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut content = String::new();
        let mut cost = 2;
        let mut count = 0;
        for ch in text.chars().skip(start as usize) {
            let escaped = serde_json::to_string(&ch.to_string())
                .map_err(|_| ErrorCode::Storage)?
                .len()
                - 2;
            if cost + escaped > cap {
                break;
            }
            content.push(ch);
            cost += escaped;
            count += 1;
        }
        let end = start + count;
        Ok(ReportChunk {
            report_id: id,
            encoding: "json_utf8_characters".into(),
            content,
            start,
            end,
            total,
            sha256: sha256(text.as_bytes()),
            truncated: end < total,
            next_start: (end < total).then_some(end),
            untrusted: true,
        })
    }

    pub fn finish_job(&self, owner: u32, job: Uuid) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        let ids: Vec<_> = state
            .reports
            .iter()
            .filter(|(_, r)| r.owner == owner && r.job == Some(job))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(report) = state.reports.remove(&id) {
                state.bytes -= report.text.len();
            }
        }
        Ok(())
    }

    pub fn maintenance(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        prune(&mut state);
        Ok(())
    }
}

fn prune(state: &mut State) {
    let now = Instant::now();
    state.reports.retain(|_, report| {
        if report.expires > now {
            true
        } else {
            state.bytes -= report.text.len();
            false
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_results_are_complete_through_bounded_unicode_chunks() {
        let reports = Reports::new(16384, 300);
        let job = Uuid::new_v4();
        let value = json!({"items":[{"snippet":"é 👩‍🔬 \"\n".repeat(100)}],"coverage":{"success":1}});
        let response = reports.bound(1001, Some(job), value.clone(), 512).unwrap();
        assert_eq!(response["truncated"], true);
        let id = serde_json::from_value(response["report_id"].clone()).unwrap();
        let mut start = 0;
        let mut combined = String::new();
        loop {
            let chunk = reports.read(1001, id, start, 32).unwrap();
            assert!(serde_json::to_vec(&chunk.content).unwrap().len() <= 32);
            combined.push_str(&chunk.content);
            match chunk.next_start {
                Some(next) => start = next,
                None => break,
            }
        }
        assert_eq!(serde_json::from_str::<Value>(&combined).unwrap(), value);
        assert!(reports.read(1002, id, 0, 32).is_err());
        reports.finish_job(1001, job).unwrap();
        assert!(reports.read(1001, id, 0, 32).is_err());
    }
}
