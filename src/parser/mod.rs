use std::collections::HashMap;
use regex::Regex;
use once_cell::sync::Lazy;
use serde_json::{Map, Value};
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
        out_map.insert("list".to_string(), Value::Array(out_list));
    }
    Value::Object(out_map)

}

fn flatten(key_name: &str, log_entry: Map<String, Value>) {
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
                       out_map.insert(ENTRIES.to_string(), Value::String(joined));
                           }
                   ENTRIES => {
                       let joined = list.into_iter().map(|x| x.to_string()).collect::<Vec<_>>().join(";");
                       out_map.insert(ENTRIES.to_string(), Value::String(joined));
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

                           out_map.insert(key.to_string(), Value::String(joined));
                       } else {
                           // Unknown content — serialize the whole array as-is
                           out_map.insert(key.to_string(), Value::Array(list));
                       }
                   }
               }
           }
           Value::Object(map) => {
               let filtered_map = map
                   .into_iter()
                   .filter(|(key, value)| !value.is_null())
                   .collect();
               let map_to_insert = JSON_TYPE_FIELDS
                   .get(key.as_str())
                   .map(|value| {});
           }
           _ => {}
       }
    }
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

pub fn parse(batch_id: i32, line: String) -> Result<(), Errors> {
    if line.is_empty() {
        Err(Errors::EmptyLine)
    } else {
        let parts: Vec<_> = line.split('\t').map(|s| s.trim()).collect();
        let log_entry = match parts[..] {
            [timestamp, ip, country, eu, subdivision,
            postal_code, isp, user_agent, request_body, request_uri] => {
                LogEntry::new(timestamp, ip, country, eu, subdivision,
                              postal_code, isp, user_agent, request_body, request_uri)
            }
            _ => return Err(Errors::ParsingError("Incorrect, different than 10 elements".to_string()))
        };
        if log_entry.body.is_empty() || log_entry.user_agent.is_empty() ||
            !log_entry.body.contains(PIXEL_GROUP_ID) {
            return Err(Errors::EmptyBody)
        }
        let maybe_body_parsed: serde_json::error::Result<Value> = serde_json::from_str(log_entry.body);
        let body_parsed = match maybe_body_parsed {
            Ok(value) => {
                match value {
                    Value::Object(map) => map,
                    _ => return Err(Errors::ParsingError("incorrect incoming string".to_string()))
                }
            }
            Err(_) => return Err(Errors::ParsingError("incorrect incoming string".to_string()))
        };
        let null_filtered: Map<String, Value> = body_parsed
            .into_iter()
            .filter(|(_, v)| handle_nulls(v))
            .collect();
        
        let action_name = match null_filtered.get("action_name") {
            None => return Err(Errors::ParsingError("action_name not detected".to_string())),
            Some(value) => match value {
                Value::String(action_name) => {
                    if !ACTION_NAMES_TO_PROCESS.contains(&&**action_name) {
                        return Err(Errors::ParsingError(format!("Skipping: {action_name}")))
                    }
                    action_name
                }
                _ => return Err(Errors::ParsingError("action_name not detected".to_string()))
            }
        };

        
        Ok(())
    }
}