use serde_json::{json, Map, Value};
use crate::errors::Errors;

#[derive(Debug)]
pub enum Enrichable {
    Gotcha(Map<String, Value>),
    PreGotcha(Map<String, Value>),
    Reported(Map<String, Value>),
    Blocked(Map<String, Value>),
    Events(Map<String, Value>),
    Warnings(Map<String, Value>),
    InitializationFailed(Map<String, Value>),
    Collection(Map<String, Value>),
    Error(Errors)
}

pub struct LineEntry {
    pub event_date: String,
    pub source_ip: String,
    pub country_code: String,
    pub eu: String,
    pub subdivision: String,
    pub postal_code: Option<String>,
    pub isp: String,
    pub raw_user_agent: String,
    pub action_name: String,
    pub request_body: Map<String, Value>,
    pub request_uri: String,
    pub batch_id: i32,
}

impl LineEntry {
    pub fn into_request_body_map(mut self) -> Enrichable {
        let mut map = std::mem::take(&mut self.request_body);

        map.insert("event_date".into(), json!(self.event_date));
        map.insert("source_ip".into(), json!(self.source_ip));
        map.insert("country_code".into(), json!(self.country_code));
        map.insert("eu".into(), json!(self.eu));
        map.insert("subdivision".into(), json!(self.subdivision));
        map.insert(
            "postal_code".into(),
            self.postal_code.map_or(Value::Null, Value::String),
        );
        map.insert("isp".into(), json!(self.isp));
        map.insert("raw_user_agent".into(), json!(self.raw_user_agent));
        map.insert("action_name".into(), json!(self.action_name));
        map.insert("request_uri".into(), json!(self.request_uri));
        map.insert("batch_id".into(), json!(self.batch_id));
        //todo we can validate schema here -> avroparser thing
        //todo I know that in enricher we discard fields based on action_name, not bothering with that now
        match self.action_name.as_str() {
            "Gotcha" => Enrichable::Gotcha(map),
            "PreGotcha" => Enrichable::PreGotcha(map),
            "Reported" => Enrichable::Reported(map),
            "Blocked" => Enrichable::Blocked(map),
            "Events" => Enrichable::Events(map),
            "Warnings" => Enrichable::Warnings(map),
            "InitializationFailed" => Enrichable::InitializationFailed(map),
            "Collection" => Enrichable::Collection(map),
            _ => Enrichable::Error(Errors::InvalidLineEntry)
        }
    }
}
