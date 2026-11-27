use serde_json::Value;

pub fn read_pointer<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() || pointer == "/" {
        return Some(value);
    }
    if !pointer.starts_with('/') {
        return None;
    }
    let mut current = value;
    for raw in pointer[1..].split('/') {
        let key = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Array(items) => {
                let index: usize = key.parse().ok()?;
                items.get(index)?
            }
            Value::Object(map) => map.get(&key)?,
            _ => return None,
        };
    }
    Some(current)
}

pub fn pointer_equals(value: &Value, pointer: &str, expected: &Value) -> bool {
    read_pointer(value, pointer) == Some(expected)
}
