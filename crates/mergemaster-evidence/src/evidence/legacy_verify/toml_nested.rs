//! CPython 3.14.7 tomllib NestedDict ownership and traversal.
use super::{Table, Value};

#[derive(Default)]
pub struct NestedDict {
    pub data: Table,
}

impl NestedDict {
    pub fn nest(&mut self, key: &[String], access_lists: bool) -> Option<&mut Table> {
        let mut cont = &mut self.data;
        for part in key {
            let index = match cont.get_index_of(part) {
                Some(index) => index,
                None => cont.insert_full(part.clone(), Value::Table(Table::new())).0,
            };
            let (_, mut value) = cont.get_index_mut(index)?;
            if access_lists && let Value::Array(items) = value {
                value = items.last_mut()?;
            }
            let Value::Table(table) = value else {
                return None;
            };
            cont = table;
        }
        Some(cont)
    }

    pub fn append_nest(&mut self, key: &[String]) -> Option<()> {
        let (stem, parent) = key.split_last()?;
        let cont = self.nest(parent, true)?;
        if let Some(index) = cont.get_index_of(stem) {
            let (_, value) = cont.get_index_mut(index)?;
            let Value::Array(items) = value else {
                return None;
            };
            items.push(Value::Table(Table::new()));
        } else {
            cont.insert(stem.clone(), Value::Array(vec![Value::Table(Table::new())]));
        }
        Some(())
    }
}

#[cfg(test)]
#[path = "toml_nested_tests.rs"]
mod tests;
