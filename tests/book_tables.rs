//! The tables of the book that are kept by hand list every Cargo feature of both crates and every
//! error code of the library. A feature or a code that the source gains without a row in its
//! table fails here.
//!
//! The codes come from a text scan of the sources, not from the compiler: the literal that
//! follows `::create(` or `ErrorPublicGenericDetails::new(` in non-test code, and the literal of
//! each arm of `KeyringError::code`. A code that reaches an error constructor through another
//! function, such as a helper that takes the code as an argument, is not found.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

/// The features that have no row in the features chapter.
const UNDOCUMENTED_FEATURES: [&str; 9] = [
    // Enables nothing.
    "default",
    // Gates of the provider features, which turn them on: `gcp` brings gcloud-sdk and the
    // conversions of its errors, `aws` brings aws-config. Neither builds a provider alone.
    "gcp",
    "aws",
    // The common part of the three Azure TLS variants. It builds only beside exactly one of them,
    // which the chapter documents instead.
    "azure-kms-encryption-base",
    // Features of the live tests that CI runs against real cloud services, never of an
    // application.
    "ci-gcp",
    "ci-aws",
    "ci-bigquery",
    "ci-tink",
    "ci-firestore-live",
];

/// A crate of the workspace and the heading of its section in the features chapter.
struct Crate {
    heading: &'static str,
    directory: &'static str,
}

const CRATES: [Crate; 2] = [
    Crate {
        heading: "kms-aead",
        directory: ".",
    },
    Crate {
        heading: "kms-aead-keyring",
        directory: "kms-aead-keyring",
    },
];

const ERROR_CODE_CONSTRUCTORS: [&str; 2] = ["::create(", "ErrorPublicGenericDetails::new("];

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The lines of the section under the `##` heading `heading`, up to the next heading.
fn section<'a>(markdown: &'a str, heading: &str) -> Vec<&'a str> {
    let heading_line = format!("## {heading}");
    markdown
        .lines()
        .skip_while(|line| *line != heading_line)
        .skip(1)
        .take_while(|line| !line.starts_with('#'))
        .collect()
}

/// The backticked names in the cells of the column `column` of every table among `lines`.
fn backticked_names(lines: &[&str], column: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut column_index = None;
    for line in lines {
        if !line.starts_with('|') {
            column_index = None;
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if let Some(header_index) = cells.iter().position(|cell| *cell == column) {
            column_index = Some(header_index);
        } else if let Some(cell) = column_index.and_then(|index| cells.get(index)) {
            names.extend(cell.split('`').skip(1).step_by(2).map(str::to_string));
        }
    }
    names
}

/// The names of the features a manifest defines in its `[features]` table. Implicit features of
/// optional dependencies have no entry there and are not features a chapter lists.
fn defined_features(manifest: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .skip_while(|line| line.trim() != "[features]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .filter(|line| line.starts_with(|first: char| first.is_ascii_alphanumeric()))
        .filter_map(|line| line.split_once('='))
        .map(|(name, _)| name.trim().to_string())
        .collect()
}

fn rust_sources(directory: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut sources = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("");
        if name == "tests" || name.starts_with("test_") {
            continue;
        }
        if path.is_dir() {
            sources.extend(rust_sources(&path)?);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(sources)
}

/// The source up to its `#[cfg(test)] mod`.
fn without_test_module(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let end = lines
        .windows(2)
        .position(|pair| pair[0].trim() == "#[cfg(test)]" && pair[1].starts_with("mod "))
        .unwrap_or(lines.len());
    lines[..end].join("\n")
}

/// The upper snake case string literals that directly follow `marker`.
fn codes_after(source: &str, marker: &str) -> BTreeSet<String> {
    source
        .match_indices(marker)
        .filter_map(|(index, _)| {
            source[index + marker.len()..]
                .trim_start()
                .strip_prefix('"')?
                .split('"')
                .next()
        })
        .filter(|literal| {
            literal.starts_with(|first: char| first.is_ascii_uppercase())
                && literal.chars().all(|character| {
                    character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
                })
        })
        .map(str::to_string)
        .collect()
}

fn error_codes_in_sources() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let keyring_errors = workspace_root().join("kms-aead-keyring/src/errors.rs");
    let mut codes = BTreeSet::new();
    for krate in &CRATES {
        let sources = rust_sources(&workspace_root().join(krate.directory).join("src"))?;
        for path in sources {
            let source = without_test_module(&fs::read_to_string(&path)?);
            for marker in ERROR_CODE_CONSTRUCTORS {
                codes.extend(codes_after(&source, marker));
            }
            if path == keyring_errors {
                codes.extend(codes_after(&source, "=>"));
            }
        }
    }
    Ok(codes)
}

#[test]
fn every_cargo_feature_has_a_row_in_the_features_chapter() -> TestResult {
    let chapter = fs::read_to_string(workspace_root().join("docs/src/features.md"))?;
    for krate in &CRATES {
        let manifest =
            fs::read_to_string(workspace_root().join(krate.directory).join("Cargo.toml"))?;
        let documented = backticked_names(&section(&chapter, krate.heading), "Feature");
        let missing: BTreeSet<String> = defined_features(&manifest)
            .into_iter()
            .filter(|feature| !UNDOCUMENTED_FEATURES.contains(&feature.as_str()))
            .filter(|feature| !documented.contains(feature))
            .collect();
        assert!(
            missing.is_empty(),
            "the {} section of features.md has no row for: {missing:?}",
            krate.heading
        );
    }
    Ok(())
}

#[test]
fn every_error_code_has_a_row_in_the_errors_chapter() -> TestResult {
    let chapter = fs::read_to_string(workspace_root().join("docs/src/errors.md"))?;
    let lines: Vec<&str> = chapter.lines().collect();
    let documented = backticked_names(&lines, "Code");
    let documented_prefixes: Vec<&str> = documented
        .iter()
        .filter_map(|name| name.strip_suffix('*'))
        .collect();
    let missing: BTreeSet<String> = error_codes_in_sources()?
        .into_iter()
        .filter(|code| !documented.contains(code))
        .filter(|code| {
            !documented_prefixes
                .iter()
                .any(|prefix| code.starts_with(prefix))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "errors.md has no row for the codes: {missing:?}"
    );
    Ok(())
}
