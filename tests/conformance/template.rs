// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The kit's template matching (`conformance/README.md`): exact values,
//! `$shape` JSON Schemas, `${name}` substitution and JSON pointers.

use std::collections::HashMap;

use regex::Regex;
use serde_json::{Map, Value};

/// Captured values, by name.
pub type Captured = HashMap<String, String>;

/// `value` with every `${name}` in every string replaced.
pub fn substitute(value: &Value, captured: &Captured) -> Value {
    match value {
        Value::String(text) => Value::String(substitute_text(text, captured)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| substitute(v, captured)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute(v, captured)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn substitute_text(text: &str, captured: &Captured) -> String {
    let mut out = text.to_owned();
    for (name, value) in captured {
        out = out.replace(&format!("${{{name}}}"), value);
    }
    out
}

/// The value at JSON pointer `at`, as a string (`String(value)` in the
/// reference runner).
pub fn pointer(body: &Value, at: &str) -> Option<String> {
    body.pointer(at).map(|value| match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    })
}

/// Every way `actual` fails `template`, with its JSON path.
pub fn mismatches(template: &Value, actual: &Value, path: &str, out: &mut Vec<String>) {
    match template {
        Value::Object(map) if map.len() == 1 && map.contains_key("$shape") => {
            schema(&map["$shape"], actual, path, out);
        }
        Value::Object(map) => objects(map, actual, path, out),
        Value::Array(items) => arrays(items, actual, path, out),
        _ if same(template, actual) => {}
        _ => out.push(format!(
            "{path}: expected {template}, got {}",
            brief(actual)
        )),
    }
}

fn arrays(items: &[Value], actual: &Value, path: &str, out: &mut Vec<String>) {
    let Some(got) = actual.as_array().filter(|got| got.len() == items.len()) else {
        out.push(format!("{path}: expected an array of {}", items.len()));
        return;
    };
    for (i, (t, a)) in items.iter().zip(got).enumerate() {
        mismatches(t, a, &format!("{path}/{i}"), out);
    }
}

fn objects(template: &Map<String, Value>, actual: &Value, path: &str, out: &mut Vec<String>) {
    let Some(got) = actual.as_object() else {
        out.push(format!("{path}: expected an object, got {}", brief(actual)));
        return;
    };
    for key in got.keys().filter(|k| !template.contains_key(*k)) {
        out.push(format!("{path}/{key}: unexpected member"));
    }
    for (key, t) in template {
        match got.get(key) {
            Some(a) => mismatches(t, a, &format!("{path}/{key}"), out),
            None => out.push(format!("{path}/{key}: missing")),
        }
    }
}

/// Equal JSON, numbers compared by value (`1` equals `1.0`).
pub fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

fn brief(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 120 {
        format!("{}...", &text[..120])
    } else {
        text
    }
}

/// The subset of JSON Schema 2020-12 the kit's `$shape`s use.
fn schema(shape: &Value, actual: &Value, path: &str, out: &mut Vec<String>) {
    let Some(shape) = shape.as_object() else {
        return;
    };
    if let Some(kind) = shape.get("type").and_then(Value::as_str) {
        if !has_type(kind, actual) {
            out.push(format!(
                "{path}: expected type {kind}, got {}",
                brief(actual)
            ));
            return;
        }
    }
    if let Some(expected) = shape.get("const") {
        if !same(expected, actual) {
            out.push(format!("{path}: expected const {expected}"));
        }
    }
    strings(shape, actual, path, out);
    members(shape, actual, path, out);
    if let (Some(items), Some(got)) = (shape.get("items"), actual.as_array()) {
        for (i, item) in got.iter().enumerate() {
            schema(items, item, &format!("{path}/{i}"), out);
        }
    }
}

fn has_type(kind: &str, actual: &Value) -> bool {
    match kind {
        "string" => actual.is_string(),
        "integer" => actual.is_i64() || actual.is_u64(),
        "number" => actual.is_number(),
        "object" => actual.is_object(),
        "array" => actual.is_array(),
        "boolean" => actual.is_boolean(),
        "null" => actual.is_null(),
        _ => false,
    }
}

fn strings(shape: &Map<String, Value>, actual: &Value, path: &str, out: &mut Vec<String>) {
    let Some(text) = actual.as_str() else {
        return;
    };
    if let Some(pattern) = shape.get("pattern").and_then(Value::as_str) {
        let re = Regex::new(pattern).expect("kit pattern compiles");
        if !re.is_match(text) {
            out.push(format!("{path}: does not match {pattern}"));
        }
    }
    let format = match shape.get("format").and_then(Value::as_str) {
        Some("uuid") => {
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        }
        Some("date-time") => r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$",
        _ => return,
    };
    if !Regex::new(format).expect("format regex").is_match(text) {
        out.push(format!("{path}: not a valid {format}"));
    }
}

fn members(shape: &Map<String, Value>, actual: &Value, path: &str, out: &mut Vec<String>) {
    let Some(got) = actual.as_object() else {
        return;
    };
    for name in shape
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = name.as_str().unwrap_or_default();
        if !got.contains_key(name) {
            out.push(format!("{path}/{name}: required"));
        }
    }
    let properties = shape.get("properties").and_then(Value::as_object);
    for (key, value) in got {
        match properties.and_then(|p| p.get(key)) {
            Some(sub) => schema(sub, value, &format!("{path}/{key}"), out),
            None => {
                if let Some(extra) = shape.get("additionalProperties") {
                    schema(extra, value, &format!("{path}/{key}"), out);
                }
            }
        }
    }
}
