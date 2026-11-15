//! Typed source limits shared by parser and streaming Git ingress.
use super::{statement_document::PolicyResource, toml, value_inputs::TextRef};
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText};
pub const SOURCE_BYTES: usize = 1_048_576;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceResource {
    Toml(toml::Resource),
    PolicyJson(PolicyResource),
    LaneJson(PolicyResource),
    RawBlob(NormalizedText),
}
impl SourceResource {
    pub fn detail(&self) -> NormalizedText {
        match self {
            Self::Toml(resource) => resource.error().message.into(),
            Self::PolicyJson(resource) => resource.message().into(),
            Self::LaneJson(resource) => match resource {
                PolicyResource::SourceBytes => "lane JSON source exceeds 1048576 bytes",
                PolicyResource::ContainerDepth => "lane JSON container depth exceeds 256",
                PolicyResource::Nodes => "lane JSON node count exceeds 262144",
            }
            .into(),
            Self::RawBlob(spec) => NormalizedText::concat(
                [spec.borrowed(), TextRef::Str(" exceeds 1048576 bytes")].into_iter(),
            ),
        }
    }
    pub fn into_error(self) -> PolicyError {
        PolicyError {
            detail: self.detail(),
            resource: Some(self),
            reason: "error",
            origin: ErrorOrigin::Failure,
        }
    }
}
