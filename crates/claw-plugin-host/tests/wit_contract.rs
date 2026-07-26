//! Conformance of the host's compiled-in constants against the WIT contract.
//!
//! The subject of every test in this file is `wit/gta-claw-plugin/world.wit`
//! itself. Expectations are *derived from the contract text* by a scanner that
//! lives only in this file, and are then compared against the constants the
//! production code actually enforces.
//!
//! This is deliberately not the same thing as the substring checks in
//! `claw_plugin_api`'s own unit tests. Those assert that the contract contains
//! some hand-written literal; they pass whether or not the Rust constants agree
//! with it. Three constants are hand-maintained copies of facts that the
//! contract states:
//!
//! * [`ABI_VERSION`] must equal the WIT package version,
//! * [`GUEST_INTERFACE`] must name the interface the world exports,
//! * [`ALLOWED_IMPORTS`] must equal the world's import list *exactly* — it is
//!   the host's deny-by-default component-import allowlist, so an entry that
//!   the contract never declared would let a component import an interface
//!   outside the ABI, and a missing entry would reject a conforming plugin.
//!
//! Nothing here calls the production parser, the production formatter, or the
//! `bindgen!`-generated bindings to build an expectation: a test that asked the
//! bindings what the bindings import could only ever prove they agree with
//! themselves.

use claw_plugin_api::WIT_WORLD;
use claw_plugin_api::abi::{ABI_VERSION, GUEST_INTERFACE};
use claw_plugin_host::ALLOWED_IMPORTS;

/// A WIT package identifier: `namespace:name@major.minor.patch`.
#[derive(Debug, PartialEq, Eq)]
struct PackageId {
    namespace: String,
    name: String,
    version: (u32, u32, u32),
}

impl PackageId {
    /// Fully qualified name of one interface in this package.
    fn interface(&self, interface: &str) -> String {
        let (major, minor, patch) = self.version;
        format!(
            "{}:{}/{interface}@{major}.{minor}.{patch}",
            self.namespace, self.name
        )
    }
}

/// Strips a `//` line comment and surrounding whitespace.
fn code(line: &str) -> &str {
    let line = line.split_once("//").map_or(line, |(before, _)| before);
    line.trim()
}

/// Reads the `package ns:name@x.y.z;` declaration out of the contract.
///
/// Panics rather than returning an option: a contract without a package
/// declaration is not a contract, and a silent `None` here would let every
/// derived expectation collapse to a vacuous pass.
fn parse_package(wit: &str) -> PackageId {
    let declaration = wit
        .lines()
        .map(code)
        .find_map(|line| line.strip_prefix("package "))
        .expect("the WIT contract must declare a package")
        .trim_end_matches(';')
        .trim();
    let (path, version) = declaration
        .split_once('@')
        .expect("the WIT package must carry an explicit version");
    let (namespace, name) = path
        .split_once(':')
        .expect("the WIT package must be `namespace:name`");
    let numbers: Vec<u32> = version
        .split('.')
        .map(|part| {
            part.parse::<u32>()
                .expect("each WIT version field must be numeric")
        })
        .collect();
    assert_eq!(
        numbers.len(),
        3,
        "the WIT package version must be major.minor.patch, got `{version}`"
    );
    PackageId {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        version: (numbers[0], numbers[1], numbers[2]),
    }
}

/// Every `import`ed and `export`ed name in the named world, in contract order.
///
/// Returns `(imports, exports)`. The scan is brace-counted from the `world`
/// header so a nested block could never be mistaken for the end of the world.
fn parse_world(wit: &str, world: &str) -> (Vec<String>, Vec<String>) {
    let header = format!("world {world} {{");
    let mut lines = wit.lines().map(code);
    lines
        .find(|line| *line == header)
        .unwrap_or_else(|| panic!("the WIT contract must declare `{header}`"));

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut depth = 1_usize;
    for line in lines {
        depth += line.matches('{').count();
        depth -= line.matches('}').count();
        if depth == 0 {
            return (imports, exports);
        }
        let Some(item) = line.strip_suffix(';') else {
            continue;
        };
        if let Some(name) = item.strip_prefix("import ") {
            imports.push(name.trim().to_owned());
        } else if let Some(name) = item.strip_prefix("export ") {
            exports.push(name.trim().to_owned());
        }
    }
    panic!("the `{world}` world is not closed");
}

#[test]
fn the_abi_version_constant_equals_the_wit_package_version() {
    let package = parse_package(WIT_WORLD);
    assert_eq!(
        (ABI_VERSION.major, ABI_VERSION.minor, ABI_VERSION.patch),
        package.version,
        "ABI_VERSION drifted from the WIT package version in {}",
        claw_plugin_api::WIT_PACKAGE_DIR
    );
    assert_eq!(package.namespace, "gta-claw");
    assert_eq!(package.name, "plugin");
}

#[test]
fn the_allowed_imports_list_is_exactly_the_world_import_list() {
    let package = parse_package(WIT_WORLD);
    let (imports, _) = parse_world(WIT_WORLD, "plugin");

    let mut expected: Vec<String> = imports
        .iter()
        .map(|interface| package.interface(interface))
        .collect();
    expected.sort();

    let mut actual: Vec<String> = ALLOWED_IMPORTS.iter().map(|s| (*s).to_owned()).collect();
    actual.sort();

    assert_eq!(
        actual, expected,
        "the host's component-import allowlist drifted from the WIT world"
    );
}

#[test]
fn the_guest_interface_constant_is_the_only_world_export() {
    let package = parse_package(WIT_WORLD);
    let (_, exports) = parse_world(WIT_WORLD, "plugin");
    let expected: Vec<String> = exports
        .iter()
        .map(|interface| package.interface(interface))
        .collect();
    assert_eq!(
        expected,
        vec![GUEST_INTERFACE.to_owned()],
        "GUEST_INTERFACE drifted from the world's export list"
    );
}

#[test]
fn the_contract_never_names_a_wasi_interface() {
    let (imports, exports) = parse_world(WIT_WORLD, "plugin");
    for name in imports.iter().chain(exports.iter()) {
        assert!(
            !name.contains("wasi"),
            "the plugin world must never reach a wasi interface, found `{name}`"
        );
    }
}

/// The scanner is itself the thing every other test in this file trusts, so it
/// is exercised against contracts whose answers are known by construction and
/// differ from the real one. Without this, a scanner that silently returned
/// nothing would make the drift tests vacuous.
mod the_scanner {
    use super::{PackageId, parse_package, parse_world};

    const SAMPLE: &str = "\
// package gta-claw:decoy@9.9.9;
package example:thing@2.5.9;

interface a {
    record r { f: u32 }
}

world other {
    import not-mine;
}

world subject {
    import alpha; // trailing comment
    import beta;

    export omega;
}
";

    #[test]
    fn it_reads_the_package_and_ignores_commented_out_declarations() {
        assert_eq!(
            parse_package(SAMPLE),
            PackageId {
                namespace: "example".to_owned(),
                name: "thing".to_owned(),
                version: (2, 5, 9),
            }
        );
    }

    #[test]
    fn it_reads_only_the_named_world() {
        let (imports, exports) = parse_world(SAMPLE, "subject");
        assert_eq!(imports, vec!["alpha".to_owned(), "beta".to_owned()]);
        assert_eq!(exports, vec!["omega".to_owned()]);

        let (other, _) = parse_world(SAMPLE, "other");
        assert_eq!(other, vec!["not-mine".to_owned()]);
    }

    #[test]
    fn it_builds_fully_qualified_interface_names() {
        assert_eq!(
            parse_package(SAMPLE).interface("alpha"),
            "example:thing/alpha@2.5.9"
        );
    }

    /// Proves the drift comparison can actually fail: an allowlist built from a
    /// contract with one extra import must not match the real allowlist.
    #[test]
    fn an_extra_import_in_the_contract_changes_the_derived_allowlist() {
        // The contract is stored with CRLF endings, so the anchor is matched
        // against a normalised copy rather than the raw bytes.
        let contract = super::WIT_WORLD.replace("\r\n", "\n");
        let tampered = contract.replace(
            "world plugin {\n    import types;",
            "world plugin {\n    import types;\n    import host-smuggled;",
        );
        assert_ne!(
            tampered, contract,
            "the tampering anchor must still match the real contract"
        );

        let package = parse_package(&tampered);
        let (imports, _) = parse_world(&tampered, "plugin");
        let derived: Vec<String> = imports
            .iter()
            .map(|interface| package.interface(interface))
            .collect();

        assert!(
            derived.contains(&"gta-claw:plugin/host-smuggled@1.0.0".to_owned()),
            "the scanner must see the smuggled import"
        );
        assert_eq!(
            derived.len(),
            super::ALLOWED_IMPORTS.len() + 1,
            "a contract with one more import must derive one more allowed name"
        );
    }
}
