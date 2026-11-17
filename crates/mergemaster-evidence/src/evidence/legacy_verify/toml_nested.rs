//! CPython 3.14.7 tomllib NestedDict ownership and traversal.
use super::{Table, Value};

#[derive(Default)]
pub struct NestedDict {
    pub data: Table,
}

impl NestedDict {
    pub fn nest(&mut self, key: &[String], access_lists: bool) -> Option<&mut Table> {
        match self.nest_charged(key, access_lists, &mut || {
            Ok::<_, std::convert::Infallible>(())
        }) {
            Ok(value) => value,
            Err(never) => match never {},
        }
    }

    pub(super) fn nest_charged<E>(
        &mut self,
        key: &[String],
        access_lists: bool,
        charge: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Option<&mut Table>, E> {
        let mut cont = &mut self.data;
        for part in key {
            let index = match cont.get_index_of(part) {
                Some(index) => index,
                None => {
                    charge()?;
                    cont.insert_full(part.clone(), Value::Table(Table::new())).0
                }
            };
            let Some((_, mut value)) = cont.get_index_mut(index) else {
                return Ok(None);
            };
            if access_lists && let Value::Array(items) = value {
                let Some(last) = items.last_mut() else {
                    return Ok(None);
                };
                value = last;
            }
            let Value::Table(table) = value else {
                return Ok(None);
            };
            cont = table;
        }
        Ok(Some(cont))
    }

    pub fn append_nest(&mut self, key: &[String]) -> Option<()> {
        match self.append_nest_charged(key, &mut || Ok::<_, std::convert::Infallible>(())) {
            Ok(value) => value,
            Err(never) => match never {},
        }
    }

    pub(super) fn append_nest_charged<E>(
        &mut self,
        key: &[String],
        charge: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Option<()>, E> {
        let Some((stem, parent)) = key.split_last() else {
            return Ok(None);
        };
        let Some(cont) = self.nest_charged(parent, true, charge)? else {
            return Ok(None);
        };
        if let Some(index) = cont.get_index_of(stem) {
            let Some((_, value)) = cont.get_index_mut(index) else {
                return Ok(None);
            };
            let Value::Array(items) = value else {
                return Ok(None);
            };
            charge()?;
            items.push(Value::Table(Table::new()));
        } else {
            charge()?; // Array node.
            charge()?; // First table node.
            cont.insert(stem.clone(), Value::Array(vec![Value::Table(Table::new())]));
        }
        Ok(Some(()))
    }
}

#[cfg(test)]
#[path = "toml_nested_tests.rs"]
mod tests;
