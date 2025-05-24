use std::collections::HashMap;
use regex::Regex;
use once_cell::sync::Lazy;
use serde_json::{json, Map, Value};
use crate::action_names::{Enrichable, LineEntry};
use crate::errors::Errors;

static EXTRACT_NGINX_VALUE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""([^"]*)""#).unwrap()
});
const PIXEL_GROUP_ID: &str = "action_group_id";
const ACTION_NAMES_TO_PROCESS: [&str; 8] = ["Gotcha", "PreGotcha", "Reported", "Blocked",
    "Events", "Warnings", "InitializationFailed", "Collection"];
const ENCODED_ENTRIES_V1: &str = "encoded_entries_v1";
const ENTRIES: &str = "entries";
const CUSTOMFIELDS: &str = "custom_fields";

//todo finish this
static JSON_TYPE_FIELDS: Lazy<HashMap<&str, &str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("action_log", "action_log_data");
    m.insert("details_json", "details_json");
    m.insert(CUSTOMFIELDS, CUSTOMFIELDS);
    m
});


fn decode_entries_encoded_in_e1(encoded: Value) -> String {
    // Only proceed if it's a string
    if let Value::String(encoded_str) = encoded {
        let mut result = String::with_capacity(encoded_str.len());
        let mut chars_left = 0;
        let mut xor_mask = 0;

        for c in encoded_str.chars() {
            if chars_left == 0 {
                chars_left = (c as u8 >> 5) + 2;
                xor_mask = ((c as u8 + 33) & 0x1F) as u8;
            } else {
                chars_left -= 1;
                let decoded_char = ((c as u8) ^ xor_mask) as char;
                result.push(decoded_char);
            }
        }

        result
    } else {
        // If not a string, return as-is
        encoded.to_string()
    }
}

fn serialize_custom_fields(field_value: Vec<Value>) -> Value {
    let mut out_map = Map::new();
    let mut out_list = Vec::new();
    for e in field_value {
        match e {
            Value::Object(map) => out_map.extend(map),
            Value::Array(arr) => out_list.extend(arr),
            _ => {}
        }
    }
    if !out_list.is_empty() {
        out_map.insert("list".to_string(), json!(out_list));
    }
    json!(out_map)

}

fn flatten(key_name: &str, log_entry: Map<String, Value>) -> Map<String, Value> {
    let mut out_map = Map::new();
    let prefix = if key_name.is_empty() {
        key_name.to_string()
    } else {
        format!("{key_name}_")
    };
    for (key, value) in log_entry {
       match value {
           Value::Array(list) => {
               match key.as_str() {
                   ENCODED_ENTRIES_V1 => {
                       let joined = list.into_iter().map(|x| decode_entries_encoded_in_e1(x)).collect::<Vec<_>>().join(";");
                       out_map.insert(ENTRIES.to_string(), json!(joined));
                           }
                   ENTRIES => {
                       let joined = list.into_iter().map(|x| x.to_string()).collect::<Vec<_>>().join(";");
                       out_map.insert(ENTRIES.to_string(), json!(joined));
                   }
                   CUSTOMFIELDS => {
                       out_map.insert(CUSTOMFIELDS.to_string(), serialize_custom_fields(list));
                   }
                   _ => {
                       if list.iter().all(|v| matches!(v, Value::String(_))) {
                           // All elements are strings — join with ";"
                           let joined = list
                               .into_iter()
                               .map(|v| v.to_string())
                               .collect::<Vec<_>>()
                               .join(";");

                           out_map.insert(key.to_string(), json!(joined));
                       } else {
                           // Unknown content — serialize the whole array as-is
                           out_map.insert(key.to_string(), json!(list));
                       }
                   }
               }
           }
           Value::Object(map) => {
               let filtered_map: Map<_, _> = map
                   .into_iter()
                   .filter(|(key, value)| !value.is_null())
                   .collect();
               let map_to_insert = JSON_TYPE_FIELDS
                   .get(key.as_str())
                   .map(|value| {
                       let mut map = Map::new();
                       map.insert(value.to_string(), json!(filtered_map));
                       map
                   })
                   .unwrap_or_else(|| flatten(format!("{prefix}{key}").as_str(), filtered_map));
               out_map.extend(map_to_insert);
           }
           value => {
               out_map.insert(format!("{prefix}{key}"), json!(value.to_string()));
           }
       }
    }
    out_map
}


fn handle_nulls(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(arr) if arr.is_empty() => false,
        Value::Array(arr) => {
            // Check if the array is [Null] or [Null, []] or [Null, [Null, ...]]
            match arr.as_slice() {
                [Value::Null] => false,
                [Value::Null, Value::Array(a)] if a.is_empty() => false,
                [Value::Null, Value::Array(a)] if a.iter().all(|v| matches!(v, Value::Null)) => false,
                _ => true
            }
        }
        _ => true,
    }
}

struct LogEntry<'a> {
    date: &'a str,
    ip: &'a str,
    country: &'a str,
    eu: &'a str,
    subdivision: &'a str,
    postal_code: Option<String>,
    isp: &'a str,
    user_agent: &'a str,
    body: &'a str,
    request_uri: &'a str
}

impl LogEntry<'_> {
    fn new<'a>(timestamp: &'a str, ip: &'a str, country: &'a str, eu: &str, subdivision: &'a str,
               postal_code: &str, isp: &'a str, user_agent: &'a str, request_body: &'a str,
               request_uri: &'a str) -> LogEntry<'a> {
        LogEntry {
            date: timestamp,
            ip,
            country,
            eu: if eu.chars().any(|ch| ch.is_ascii_digit()) { "true" } else { "false" },
            subdivision,
            postal_code: {
                EXTRACT_NGINX_VALUE_REGEX
                    .find(postal_code)
                    .map(|m| m.as_str().replace('"', ""))
            },
            isp,
            user_agent,
            body: request_body,
            request_uri
        }
    }
}

pub fn parse(batch_id: i32, line: String) -> Enrichable {
    if line.is_empty() {
        Enrichable::Error(Errors::EmptyLine)
    } else {
        let parts: Vec<_> = line.split('\t').map(|s| s.trim()).collect();
        let log_entry = match parts[..] {
            [timestamp, ip, country, eu, subdivision,
            postal_code, isp, user_agent, request_body, request_uri] => {
                LogEntry::new(timestamp, ip, country, eu, subdivision,
                              postal_code, isp, user_agent, request_body, request_uri)
            }
            _ => return Enrichable::Error(Errors::ParsingError("Incorrect, different than 10 elements".to_string()))
        };
        if log_entry.body.is_empty() || log_entry.user_agent.is_empty() ||
            !log_entry.body.contains(PIXEL_GROUP_ID) {
            return Enrichable::Error(Errors::EmptyBody)
        }
        let maybe_body_parsed: serde_json::error::Result<Value> = serde_json::from_str(log_entry.body);
        let body_parsed = match maybe_body_parsed {
            Ok(value) => {
                match value {
                    Value::Object(map) => map,
                    _ => return Enrichable::Error(Errors::ParsingError("incorrect incoming string".to_string()))
                }
            }
            Err(_) => return Enrichable::Error(Errors::ParsingError("incorrect incoming string".to_string()))
        };
        let null_filtered: Map<String, Value> = body_parsed
            .into_iter()
            .filter(|(_, v)| handle_nulls(v))
            .collect();

        let action_name = match null_filtered.get("action_name").and_then(|v| {
            if let Value::String(s) = v {
                Some(s)
            } else {
                None
            }
        }) {
            Some(s) if ACTION_NAMES_TO_PROCESS.contains(&&**s) => s.clone(),
            Some(s) => return Enrichable::Error(Errors::ParsingError(format!("Skipping: {s}"))),
            None => return Enrichable::Error(Errors::ParsingError("action_name not detected".to_string())),
        };

        let parsed_body_request = flatten("", null_filtered);

        let line_entry = LineEntry {
            event_date: log_entry.date.to_string(),
            source_ip: log_entry.ip.to_string(),
            country_code: log_entry.country.to_string(),
            subdivision: log_entry.subdivision.to_string(),
            postal_code: log_entry.postal_code,
            eu: log_entry.eu.to_string(),
            isp: log_entry.isp.to_string(),
            raw_user_agent: log_entry.user_agent.to_string(),
            action_name,
            request_body: parsed_body_request,
            request_uri: log_entry.request_uri.to_string(),
            batch_id
        };
        line_entry.into_request_body_map()
    }
}