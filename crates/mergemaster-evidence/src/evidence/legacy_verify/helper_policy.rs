//! Lossless normalized policy-rules output for the import helper.
use super::failure_json::TextRef;
use crate::evidence::{
    legacy_output::{self, Object, ValueWriter, Written},
    legacy_policy::{
        CommandInputs, ErrorOrigin, PolicyDocument, PolicyError, RequireMode,
        kind_rules::KindRule,
        level_rules::{LaneBinding, LevelRule},
        normalized_text::NormalizedText,
        value_rules::ShardInputs,
    },
};
use std::fmt;

pub(super) fn write(
    text: &str,
    check: TextRef<'_>,
    repository: TextRef<'_>,
    output: &mut String,
) -> Result<(), PolicyError> {
    let document = match check {
        TextRef::Str(check) => PolicyDocument::parse(text, check),
        TextRef::Points(check) => PolicyDocument::parse(text, check),
    }?;
    let rules = document.into_rules(repository)?;
    legacy_output::write(output, |writer| {
        writer.object(|object| {
            object.field_text("kinds", |writer| {
                writer.object(|object| {
                    for (name, rule) in &rules.kinds {
                        object.field_text(name, |writer| kind(writer, rule))?;
                    }
                    Ok(())
                })
            })?;
            let header = &rules.header;
            object.field_text("trust_levels", |writer| texts(writer, &header.trust_levels))?;
            object.field_text("max_age_s", |writer| match &header.max_age_s {
                Some(seconds) => writer.policy_seconds(seconds),
                None => writer.null(),
            })?;
            object.field_text("enforce", |writer| writer.boolean(header.enforce))?;
            object.field_text("inputs", |writer| match &header.inputs {
                Some(inputs) => texts(writer, inputs),
                None => writer.null(),
            })?;
            object.field_text("sample_one_in", |writer| {
                writer.integer(i128::from(header.sample_one_in))
            })?;
            object.field_text("require", |writer| {
                writer.text(match header.require {
                    RequireMode::Off => "off",
                    RequireMode::Shadow => "shadow",
                    RequireMode::Reject => "reject",
                })
            })?;
            object.field_text("events", |writer| match &header.events {
                Some(events) => strings(writer, events),
                None => writer.null(),
            })
        })
    })
    .map_err(|_| PolicyError {
        reason: "error",
        detail: "could not serialize policy rules".into(),
        origin: ErrorOrigin::Failure,
        resource: None,
    })
}

fn text<'s>(
    writer: ValueWriter<'s, '_, String>,
    value: &NormalizedText,
) -> Result<Written<'s>, fmt::Error> {
    writer.codepoints(value.borrowed().points())
}

fn texts<'s>(
    writer: ValueWriter<'s, '_, String>,
    values: &[NormalizedText],
) -> Result<Written<'s>, fmt::Error> {
    writer.array(|array| {
        for value in values {
            array.item(|writer| text(writer, value))?;
        }
        Ok(())
    })
}

fn strings<'s>(
    writer: ValueWriter<'s, '_, String>,
    values: &[String],
) -> Result<Written<'s>, fmt::Error> {
    writer.array(|array| {
        for value in values {
            array.item(|writer| writer.text(value))?;
        }
        Ok(())
    })
}

fn field(
    object: &mut Object<'_, String>,
    key: &NormalizedText,
    value: impl for<'s> FnOnce(ValueWriter<'s, '_, String>) -> Result<Written<'s>, fmt::Error>,
) -> fmt::Result {
    match key {
        NormalizedText::Scalar(key) => object.field_text(key, value),
        NormalizedText::Codepoints(key) => object.field(key, value),
    }
}

fn input_fields(object: &mut Object<'_, String>, inputs: &CommandInputs) -> fmt::Result {
    object.field_text("required_inputs", |writer| {
        texts(writer, &inputs.required_inputs)
    })?;
    object.field_text("bind_inputs", |writer| {
        writer.object(|object| {
            for (key, value) in &inputs.bind_inputs {
                field(object, key, |writer| text(writer, value))?;
            }
            Ok(())
        })
    })
}

fn kind<'s>(
    writer: ValueWriter<'s, '_, String>,
    rule: &KindRule,
) -> Result<Written<'s>, fmt::Error> {
    writer.object(|object| {
        object.field_text("command", |writer| texts(writer, &rule.inputs.command))?;
        object.field_text("runner_prefix", |writer| match &rule.runner_prefix {
            Some(prefix) => text(writer, prefix),
            None => writer.null(),
        })?;
        input_fields(object, &rule.inputs)?;
        object.field_text("trust_levels", |writer| match &rule.trust_levels {
            Some(levels) => texts(writer, levels),
            None => writer.null(),
        })?;
        object.field_text("by_level", |writer| {
            writer.object(|object| {
                for (name, rule) in &rule.by_level {
                    field(object, name, |writer| level(writer, rule))?;
                }
                Ok(())
            })
        })?;
        object.field_text("input_order", |writer| {
            writer.object(|object| {
                for (key, values) in &rule.values.input_order {
                    field(object, key, |writer| texts(writer, values))?;
                }
                Ok(())
            })
        })?;
        object.field_text("shard_inputs", |writer| match &rule.values.shard_inputs {
            Some(shards) => shard_inputs(writer, shards),
            None => writer.null(),
        })?;
        object.field_text("base_inputs", |writer| {
            writer.object(|object| {
                for (key, path) in &rule.base_inputs {
                    field(object, key, |writer| writer.text(path))?;
                }
                Ok(())
            })
        })
    })
}

fn level<'s>(
    writer: ValueWriter<'s, '_, String>,
    rule: &LevelRule,
) -> Result<Written<'s>, fmt::Error> {
    writer.object(|object| {
        object.field_text("command", |writer| texts(writer, &rule.inputs.command))?;
        input_fields(object, &rule.inputs)?;
        object.field_text("events", |writer| strings(writer, &rule.events))?;
        object.field_text("lane", |writer| match rule.lane {
            LaneBinding::None => writer.boolean(false),
            LaneBinding::Base => writer.boolean(true),
            LaneBinding::Tree => writer.text("tree"),
        })
    })
}

fn shard_inputs<'s>(
    writer: ValueWriter<'s, '_, String>,
    shards: &ShardInputs,
) -> Result<Written<'s>, fmt::Error> {
    writer.object(|object| {
        object.field_text("count", |writer| text(writer, &shards.count))?;
        object.field_text("results", |writer| text(writer, &shards.results))?;
        if let Some(count) = shards.pull_request_count {
            object.field_text("pull_request_count", |writer| match count {
                Some(count) => writer.integer(i128::from(count)),
                None => writer.null(),
            })?;
        }
        if let Some(index) = &shards.index {
            object.field_text("index", |writer| text(writer, index))?;
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "helper_policy_tests.rs"]
mod tests;
