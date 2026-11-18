//! Typed source limits shared by parser and streaming Git ingress.
use super::{statement_document::PolicyResource, toml, value_inputs::TextRef};
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText};
pub const SOURCE_BYTES: usize = 1_048_576;
pub const LISTING_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceResource {
    Toml(toml::Resource),
    PolicyJson(PolicyResource),
    LaneJson(PolicyResource),
    CrateInputsNodes,
    PathDependencyDepth,
    PathDependencyCrates,
    RawBlob(NormalizedText),
    TreeListing(NormalizedText),
}
impl SourceResource {
    pub fn byte_limit(&self) -> usize {
        match self {
            Self::TreeListing(_) => LISTING_BYTES,
            _ => SOURCE_BYTES,
        }
    }
    pub fn detail(&self) -> NormalizedText {
        match self {
            Self::Toml(resource) => resource.error().message.into(),
            Self::PolicyJson(resource) => resource.message().into(),
            Self::CrateInputsNodes => "crate inputs JSON node count exceeds 262144".into(),
            Self::PathDependencyDepth => "path dependency depth exceeds 256".into(),
            Self::PathDependencyCrates => "path dependency crate count exceeds 1024".into(),
            Self::LaneJson(resource) => match resource {
                PolicyResource::SourceBytes => "lane JSON source exceeds 1048576 bytes",
                PolicyResource::ContainerDepth => "lane JSON container depth exceeds 256",
                PolicyResource::Nodes => "lane JSON node count exceeds 262144",
            }
            .into(),
            Self::RawBlob(spec) => NormalizedText::concat(
                [spec.borrowed(), TextRef::Str(" exceeds 1048576 bytes")].into_iter(),
            ),
            Self::TreeListing(spec) => {
                NormalizedText::around("", spec.borrowed(), " exceeds 67108864 bytes")
            }
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
