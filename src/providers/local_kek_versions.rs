use std::collections::BTreeMap;

use super::{LocalKekId, LocalKekVersion};
use crate::errors::KmsAeadSystemError;
use crate::KmsAeadResult;

/// The versions of a local KEK, each with what it holds and where it was loaded from, and the
/// version that encrypts: the highest unless set to another.
#[derive(Debug)]
pub(crate) struct LocalKekVersions<T> {
    id: LocalKekId,
    versions: BTreeMap<LocalKekVersion, Source<T>>,
    /// Always a key of `versions`.
    encrypting_version: LocalKekVersion,
}

#[derive(Debug)]
struct Source<T> {
    origin: String,
    held: T,
}

impl<T> LocalKekVersions<T> {
    /// The versions of the KEK `id`, each as its version, where it came from (for the log line)
    /// and what it holds.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_VERSIONS` when `versions` is empty or lists a version twice.
    pub(crate) fn new(
        id: LocalKekId,
        versions: Vec<(LocalKekVersion, String, T)>,
    ) -> KmsAeadResult<Self> {
        let mut by_version = BTreeMap::new();
        for (version, origin, held) in versions {
            if by_version
                .insert(version, Source { origin, held })
                .is_some()
            {
                return Err(KmsAeadSystemError::create(
                    "LOCAL_KEK_VERSIONS",
                    &format!("The local KEK {id} lists version {version} twice"),
                ));
            }
        }
        let Some(&encrypting_version) = by_version.keys().next_back() else {
            return Err(KmsAeadSystemError::create(
                "LOCAL_KEK_VERSIONS",
                &format!("The local KEK {id} has no version"),
            ));
        };
        Ok(Self {
            id,
            versions: by_version,
            encrypting_version,
        })
    }

    /// What `version` holds, if the KEK lists it.
    pub(crate) fn get(&self, version: LocalKekVersion) -> Option<&T> {
        self.versions.get(&version).map(|source| &source.held)
    }

    pub(crate) fn encrypting_version(&self) -> LocalKekVersion {
        self.encrypting_version
    }

    /// The versions in ascending order.
    pub(crate) fn versions(&self) -> impl Iterator<Item = LocalKekVersion> + '_ {
        self.versions.keys().copied()
    }

    /// Each version with where it came from, `1 (file orders.key), 2 (env ORDERS_KEK)`.
    pub(crate) fn listing(&self) -> String {
        self.versions
            .iter()
            .map(|(version, source)| format!("{version} ({})", source.origin))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The same versions with `version` encrypting in place of the highest.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_VERSIONS` when the KEK does not list `version`.
    pub(crate) fn with_encrypting_version(
        mut self,
        version: LocalKekVersion,
    ) -> KmsAeadResult<Self> {
        if !self.versions.contains_key(&version) {
            return Err(KmsAeadSystemError::create(
                "LOCAL_KEK_VERSIONS",
                &format!(
                    "The local KEK {} does not list version {version} to encrypt with",
                    self.id
                ),
            ));
        }
        self.encrypting_version = version;
        Ok(self)
    }
}
