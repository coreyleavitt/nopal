use serde::Serialize;
use serde_json::Value;

/// Top-level nftables JSON structure accepted by `nft -j -f -`.
///
/// The nftables CLI in JSON mode expects a single object with a `"nftables"`
/// key whose value is an array of command objects. Each command is one of
/// flush, table, chain, or rule.
#[derive(Debug, Serialize)]
pub struct Ruleset {
    pub nftables: Vec<NftCommand>,
}

/// Individual nftables commands within a ruleset.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NftCommand {
    Flush(FlushCmd),
    Table(TableDef),
    Chain(ChainDef),
    Rule(RuleDef),
    Map(MapDef),
    Set(SetDef),
}

/// Named map definition for dynamic key-value lookups (e.g. sticky sessions).
#[derive(Debug, Serialize)]
pub struct MapDef {
    pub family: String,
    pub table: String,
    pub name: String,
    /// Key type: a string like `"ipv4_addr"` or an array for concatenated
    /// keys like `["ipv4_addr", "ipv4_addr"]`.
    #[serde(rename = "type")]
    pub key_type: Value,
    /// Value type that the map returns (e.g. `"mark"`).
    pub map: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

/// Named set definition for user-populated dynamic bypass sets.
#[derive(Debug, Serialize)]
pub struct SetDef {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(rename = "type")]
    pub set_type: String,
    pub flags: Vec<String>,
}

/// Flush command -- used to clear all rules from the table before rebuilding.
#[derive(Debug, Serialize)]
pub struct FlushCmd {
    pub table: TableRef,
}

/// Reference to a table (used inside flush and as a standalone field).
#[derive(Debug, Serialize)]
pub struct TableRef {
    pub family: String,
    pub name: String,
}

/// Table definition.
#[derive(Debug, Serialize)]
pub struct TableDef {
    pub family: String,
    pub name: String,
}

/// Chain definition. Base chains have `type_`, `hook`, `prio`, and `policy`
/// set. Regular chains leave these as `None`.
#[derive(Debug, Serialize)]
pub struct ChainDef {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prio: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// Rule definition. Expressions are kept as raw `serde_json::Value` to
/// accommodate the full complexity of the nftables JSON expression format
/// without requiring exhaustive type definitions.
#[derive(Debug, Serialize)]
pub struct RuleDef {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub expr: Vec<Value>,
}

impl Ruleset {
    /// Create an empty ruleset.
    pub fn new() -> Self {
        Self {
            nftables: Vec::new(),
        }
    }

    /// Append a flush-table command.
    pub fn flush_table(&mut self, family: &str, name: &str) {
        self.nftables.push(NftCommand::Flush(FlushCmd {
            table: TableRef {
                family: family.to_string(),
                name: name.to_string(),
            },
        }));
    }

    /// Append a table definition.
    pub fn add_table(&mut self, family: &str, name: &str) {
        self.nftables.push(NftCommand::Table(TableDef {
            family: family.to_string(),
            name: name.to_string(),
        }));
    }

    /// Append a base chain (with hook/priority/policy).
    pub fn add_base_chain(
        &mut self,
        name: &str,
        type_: &str,
        hook: &str,
        prio: i32,
        policy: &str,
    ) {
        self.nftables.push(NftCommand::Chain(ChainDef {
            family: TABLE_FAMILY.to_string(),
            table: TABLE_NAME.to_string(),
            name: name.to_string(),
            type_: Some(type_.to_string()),
            hook: Some(hook.to_string()),
            prio: Some(prio),
            policy: Some(policy.to_string()),
        }));
    }

    /// Append a regular (non-base) chain.
    pub fn add_regular_chain(&mut self, name: &str) {
        self.nftables.push(NftCommand::Chain(ChainDef {
            family: TABLE_FAMILY.to_string(),
            table: TABLE_NAME.to_string(),
            name: name.to_string(),
            type_: None,
            hook: None,
            prio: None,
            policy: None,
        }));
    }

    /// Append a named map definition.
    pub fn add_map(
        &mut self,
        name: &str,
        key_type: Value,
        value_type: &str,
        timeout: u32,
    ) {
        self.nftables.push(NftCommand::Map(MapDef {
            family: TABLE_FAMILY.to_string(),
            table: TABLE_NAME.to_string(),
            name: name.to_string(),
            key_type,
            map: value_type.to_string(),
            flags: vec!["timeout".to_string()],
            timeout: Some(timeout),
        }));
    }

    /// Append a named set definition.
    pub fn add_set(&mut self, name: &str, set_type: &str, flags: Vec<String>) {
        self.nftables.push(NftCommand::Set(SetDef {
            family: TABLE_FAMILY.to_string(),
            table: TABLE_NAME.to_string(),
            name: name.to_string(),
            set_type: set_type.to_string(),
            flags,
        }));
    }

    /// Append a rule with the given expression list.
    pub fn add_rule(&mut self, chain: &str, expr: Vec<Value>) {
        self.nftables.push(NftCommand::Rule(RuleDef {
            family: TABLE_FAMILY.to_string(),
            table: TABLE_NAME.to_string(),
            chain: chain.to_string(),
            expr,
        }));
    }
}

/// The nftables table family used by nopal.
pub const TABLE_FAMILY: &str = "inet";
/// The nftables table name used by nopal.
pub const TABLE_NAME: &str = "nopal";
/// Mark value used by probe sockets (SO_MARK) to bypass nopal rules.
pub const PROBE_MARK: u32 = 0xDEAD;
