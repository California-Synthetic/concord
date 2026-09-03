use anyhow::{ensure, Context, Result};
pub use concord_protocol::{
    ApprovalMode, CapabilityPermission, EffectClass, ReversibilityClass, ReversibilityPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const CAPABILITY_PACKAGE_CONTRACT: &str = "concord.capability-package/1";
pub const MCP_DISCOVERY_CONTRACT: &str = "concord.mcp-discovery/1";
pub const CAPABILITY_QUALIFICATION_CONTRACT: &str = "concord.capability-qualification/1";

const SUPPORTED_MCP_PROTOCOLS: &[&str] = &["2025-06-18", "2025-11-25", "2026-07-28"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPackageKind {
    AgentSkill,
    McpServer,
    ConcordNative,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTransport {
    Directory,
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CapabilityAuthentication {
    #[default]
    None,
    BearerEnvironment {
        key: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageTrustStatus {
    Quarantined,
    Inspected,
    Qualified,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPackageSource {
    pub uri: String,
    pub transport: CapabilityTransport,
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Names of credentials or configuration values resolved by Concord at execution time.
    /// Values are deliberately not part of the portable package contract.
    #[serde(default)]
    pub environment_keys: Vec<String>,
    #[serde(default)]
    pub protocol_versions: Vec<String>,
    #[serde(default)]
    pub authentication: CapabilityAuthentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPackage {
    pub contract: String,
    pub package_id: String,
    pub display_name: String,
    pub version: String,
    pub kind: CapabilityPackageKind,
    pub source: CapabilityPackageSource,
    /// SHA-256 of the complete imported directory, archive, native package, or frozen MCP
    /// discovery record. It is identity evidence, not a trust decision.
    pub content_sha256: String,
    pub trust_status: PackageTrustStatus,
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<CapabilityPermission>,
    /// Preserved from Agent Skills' experimental `allowed-tools` field. Concord never uses
    /// this field to bypass its own permission and approval policy.
    #[serde(default)]
    pub upstream_allowed_tools: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolSnapshot {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(default)]
    pub output_schema: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpDiscoverySnapshot {
    pub contract: String,
    pub package_id: String,
    pub protocol_version: String,
    pub server_name: String,
    pub server_version: String,
    pub discovered_at: String,
    pub tools: Vec<McpToolSnapshot>,
    pub discovery_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredCapabilityPackage {
    pub record_id: String,
    pub package: CapabilityPackage,
    pub registered_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpDiscoveryRecord {
    pub record_id: String,
    pub package_record_id: String,
    pub package_content_sha256: String,
    pub snapshot: McpDiscoverySnapshot,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QualificationDisposition {
    Inspected,
    Qualified,
    Rejected,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityToolPolicy {
    pub tool_name: String,
    pub effect: EffectClass,
    pub approval: ApprovalMode,
    #[serde(default)]
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "ReversibilityPolicy::is_unspecified")]
    pub reversibility: ReversibilityPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityQualification {
    pub contract: String,
    pub record_id: String,
    pub package_record_id: String,
    pub package_content_sha256: String,
    #[serde(default)]
    pub discovery_record_id: Option<String>,
    #[serde(default)]
    pub discovery_sha256: Option<String>,
    pub disposition: QualificationDisposition,
    #[serde(default)]
    pub tool_policies: Vec<CapabilityToolPolicy>,
    pub inspector: String,
    pub rationale: String,
    #[serde(default)]
    pub previous_qualification_sha256: Option<String>,
    pub qualification_sha256: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QualifiedMcpToolBinding {
    pub alias: String,
    pub package_record_id: String,
    pub package_id: String,
    pub package_display_name: String,
    pub package_content_sha256: String,
    pub qualification_record_id: String,
    pub qualification_sha256: String,
    pub discovery_record_id: String,
    pub discovery_sha256: String,
    pub source: CapabilityPackageSource,
    pub tool: McpToolSnapshot,
    pub policy: CapabilityToolPolicy,
}

pub fn qualified_mcp_tool_alias(qualification_sha256: &str, tool_name: &str) -> Result<String> {
    validate_sha256(qualification_sha256)?;
    ensure!(
        !tool_name.trim().is_empty(),
        "qualified MCP tool name is required"
    );
    let tool_sha256 = format!("{:x}", Sha256::digest(tool_name.as_bytes()));
    Ok(format!(
        "mcp_{}_{}",
        &qualification_sha256[..12],
        &tool_sha256[..12]
    ))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QualificationHashInput<'a> {
    contract: &'a str,
    package_record_id: &'a str,
    package_content_sha256: &'a str,
    discovery_record_id: &'a Option<String>,
    discovery_sha256: &'a Option<String>,
    disposition: QualificationDisposition,
    tool_policies: &'a [CapabilityToolPolicy],
    inspector: &'a str,
    rationale: &'a str,
    previous_qualification_sha256: &'a Option<String>,
    recorded_at: &'a str,
}

impl CapabilityQualification {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        package_record_id: String,
        package_content_sha256: String,
        discovery_record_id: Option<String>,
        discovery_sha256: Option<String>,
        disposition: QualificationDisposition,
        mut tool_policies: Vec<CapabilityToolPolicy>,
        inspector: String,
        rationale: String,
        previous_qualification_sha256: Option<String>,
        recorded_at: String,
    ) -> Result<Self> {
        if disposition == QualificationDisposition::Qualified {
            ensure!(
                tool_policies
                    .iter()
                    .all(|policy| !policy.reversibility.is_unspecified()),
                "qualified tool policies require an explicit reversibility contract"
            );
        }
        tool_policies.sort_by(|left, right| left.tool_name.cmp(&right.tool_name));
        let contract = CAPABILITY_QUALIFICATION_CONTRACT.to_owned();
        let input = QualificationHashInput {
            contract: &contract,
            package_record_id: &package_record_id,
            package_content_sha256: &package_content_sha256,
            discovery_record_id: &discovery_record_id,
            discovery_sha256: &discovery_sha256,
            disposition,
            tool_policies: &tool_policies,
            inspector: inspector.trim(),
            rationale: rationale.trim(),
            previous_qualification_sha256: &previous_qualification_sha256,
            recorded_at: &recorded_at,
        };
        let qualification_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&input)?));
        let record_id = format!("capqual_{}", &qualification_sha256[..24]);
        let qualification = Self {
            contract,
            record_id,
            package_record_id,
            package_content_sha256,
            discovery_record_id,
            discovery_sha256,
            disposition,
            tool_policies,
            inspector: inspector.trim().to_owned(),
            rationale: rationale.trim().to_owned(),
            previous_qualification_sha256,
            qualification_sha256,
            recorded_at,
        };
        qualification.validate()?;
        Ok(qualification)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract == CAPABILITY_QUALIFICATION_CONTRACT,
            "unsupported capability qualification contract {}",
            self.contract
        );
        validate_sha256(&self.package_content_sha256)?;
        validate_sha256(&self.qualification_sha256)?;
        ensure!(
            self.record_id == format!("capqual_{}", &self.qualification_sha256[..24]),
            "capability qualification record identity mismatch"
        );
        if let Some(value) = &self.discovery_sha256 {
            validate_sha256(value)?;
        }
        if let Some(value) = &self.previous_qualification_sha256 {
            validate_sha256(value)?;
        }
        ensure!(
            !self.inspector.is_empty(),
            "qualification inspector is required"
        );
        ensure!(
            !self.rationale.is_empty(),
            "qualification rationale is required"
        );
        ensure!(
            self.inspector.len() <= 256,
            "qualification inspector exceeds 256 characters"
        );
        ensure!(
            self.rationale.len() <= 10_000,
            "qualification rationale exceeds 10000 characters"
        );
        ensure!(
            !self.package_record_id.trim().is_empty(),
            "qualification package record id is required"
        );
        ensure!(
            self.discovery_record_id.is_some() == self.discovery_sha256.is_some(),
            "qualification discovery record and digest must be supplied together"
        );
        let mut names = BTreeSet::new();
        let mut previous_name: Option<&str> = None;
        for policy in &self.tool_policies {
            ensure!(
                !policy.tool_name.trim().is_empty(),
                "tool policy name is required"
            );
            ensure!(
                policy.tool_name.len() <= 256,
                "tool policy name exceeds 256 characters"
            );
            ensure!(
                names.insert(policy.tool_name.as_str()),
                "duplicate tool policy {}",
                policy.tool_name
            );
            ensure!(
                previous_name.is_none_or(|previous| previous < policy.tool_name.as_str()),
                "tool policies must be sorted by tool name"
            );
            previous_name = Some(&policy.tool_name);
            ensure!(
                !matches!(policy.approval, ApprovalMode::Never)
                    || matches!(policy.effect, EffectClass::ReadOnly),
                "only read-only tools may be qualified without approval"
            );
            policy.reversibility.validate(policy.effect.clone())?;
            let mut data_classes = BTreeSet::new();
            for data_class in &policy.data_classes {
                ensure!(
                    !data_class.trim().is_empty() && data_class.len() <= 128,
                    "tool policy data classes must contain 1-128 characters"
                );
                ensure!(
                    data_classes.insert(data_class),
                    "duplicate tool policy data class {data_class}"
                );
            }
        }
        if self.disposition != QualificationDisposition::Qualified {
            ensure!(
                self.tool_policies.is_empty(),
                "only a qualified decision may grant tool policies"
            );
        } else {
            ensure!(
                self.discovery_record_id.is_some(),
                "qualified execution requires a frozen discovery record"
            );
        }
        let input = QualificationHashInput {
            contract: &self.contract,
            package_record_id: &self.package_record_id,
            package_content_sha256: &self.package_content_sha256,
            discovery_record_id: &self.discovery_record_id,
            discovery_sha256: &self.discovery_sha256,
            disposition: self.disposition,
            tool_policies: &self.tool_policies,
            inspector: &self.inspector,
            rationale: &self.rationale,
            previous_qualification_sha256: &self.previous_qualification_sha256,
            recorded_at: &self.recorded_at,
        };
        let expected = format!("{:x}", Sha256::digest(serde_json::to_vec(&input)?));
        ensure!(
            self.qualification_sha256 == expected,
            "capability qualification digest mismatch"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct AgentSkillFrontmatter {
    name: String,
    description: String,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    compatibility: Option<String>,
    #[serde(default)]
    metadata: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    allowed_tools: Option<String>,
}

/// Inspect and hash an Agent Skills directory without executing any bundled code.
///
/// The returned package is always quarantined. Qualification and effect permissions are
/// deliberately separate operations owned by Concord.
pub fn inspect_agent_skill_directory(root: &Path) -> Result<CapabilityPackage> {
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize Agent Skill directory {}", root.display()))?;
    ensure!(root.is_dir(), "Agent Skill source must be a directory");
    let skill_path = root.join("SKILL.md");
    ensure!(
        skill_path.is_file(),
        "Agent Skill directory must contain SKILL.md"
    );
    let skill_text = fs::read_to_string(&skill_path)
        .with_context(|| format!("read {}", skill_path.display()))?;
    let frontmatter_text = yaml_frontmatter(&skill_text)?;
    let frontmatter: AgentSkillFrontmatter = serde_yaml_ng::from_str(frontmatter_text)
        .with_context(|| format!("parse {} frontmatter", skill_path.display()))?;
    validate_agent_skill_name(&frontmatter.name)?;
    ensure!(
        root.file_name().and_then(|value| value.to_str()) == Some(frontmatter.name.as_str()),
        "Agent Skill name must match its parent directory"
    );
    ensure!(
        (1..=1024).contains(&frontmatter.description.len()),
        "Agent Skill description must contain 1-1024 characters"
    );
    if let Some(compatibility) = &frontmatter.compatibility {
        ensure!(
            (1..=500).contains(&compatibility.len()),
            "Agent Skill compatibility must contain 1-500 characters"
        );
    }

    let (content_sha256, file_count, byte_count) = hash_directory(&root)?;
    let upstream_allowed_tools = frontmatter
        .allowed_tools
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let version = frontmatter
        .metadata
        .get("version")
        .cloned()
        .unwrap_or_else(|| format!("0.0.0+sha.{}", &content_sha256[..12]));
    let package = CapabilityPackage {
        contract: CAPABILITY_PACKAGE_CONTRACT.to_owned(),
        package_id: format!("agentskills/{}", frontmatter.name),
        display_name: frontmatter.name.clone(),
        version,
        kind: CapabilityPackageKind::AgentSkill,
        source: CapabilityPackageSource {
            uri: format!("file://{}", root.display()),
            transport: CapabilityTransport::Directory,
            entrypoint: Some("SKILL.md".to_owned()),
            arguments: vec![],
            environment_keys: vec![],
            protocol_versions: vec![],
            authentication: CapabilityAuthentication::None,
        },
        content_sha256,
        trust_status: PackageTrustStatus::Quarantined,
        declared_capabilities: vec!["agent_skill".to_owned()],
        permissions: vec![],
        upstream_allowed_tools,
        metadata: serde_json::json!({
            "sourceFormat": "agentskills.io/1",
            "description": frontmatter.description,
            "license": frontmatter.license,
            "compatibility": frontmatter.compatibility,
            "upstreamMetadata": frontmatter.metadata,
            "fileCount": file_count,
            "byteCount": byte_count,
        }),
    };
    package.validate()?;
    Ok(package)
}

impl CapabilityPackage {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract == CAPABILITY_PACKAGE_CONTRACT,
            "unsupported capability package contract {}",
            self.contract
        );
        validate_package_id(&self.package_id)?;
        ensure!(
            !self.display_name.trim().is_empty(),
            "display name is required"
        );
        ensure!(
            !self.version.trim().is_empty(),
            "package version is required"
        );
        validate_sha256(&self.content_sha256)?;
        ensure!(
            !self.source.uri.trim().is_empty(),
            "package source URI is required"
        );
        ensure!(
            !contains_embedded_credential(&self.source.uri),
            "package source URI must not embed credentials"
        );

        let mut environment_keys = BTreeSet::new();
        for key in &self.source.environment_keys {
            ensure!(valid_environment_key(key), "invalid environment key {key}");
            ensure!(
                environment_keys.insert(key),
                "duplicate environment key {key}"
            );
        }
        match &self.source.authentication {
            CapabilityAuthentication::None => {}
            CapabilityAuthentication::BearerEnvironment { key } => {
                ensure!(
                    valid_environment_key(key),
                    "invalid bearer authentication environment key {key}"
                );
                ensure!(
                    self.source.environment_keys.contains(key),
                    "bearer authentication key must be declared in environmentKeys"
                );
            }
        }

        match self.kind {
            CapabilityPackageKind::AgentSkill => {
                ensure!(
                    self.source.transport == CapabilityTransport::Directory,
                    "Agent Skills must be imported as directories"
                );
                ensure!(
                    self.source.entrypoint.as_deref() == Some("SKILL.md"),
                    "Agent Skills must use SKILL.md as the entrypoint"
                );
                ensure!(
                    self.source.protocol_versions.is_empty(),
                    "Agent Skills do not declare MCP protocol versions"
                );
            }
            CapabilityPackageKind::McpServer => {
                ensure!(
                    matches!(
                        self.source.transport,
                        CapabilityTransport::Stdio | CapabilityTransport::StreamableHttp
                    ),
                    "MCP servers require stdio or streamable HTTP"
                );
                ensure!(
                    !self.source.protocol_versions.is_empty(),
                    "MCP packages must declare at least one protocol version"
                );
                for version in &self.source.protocol_versions {
                    ensure!(
                        SUPPORTED_MCP_PROTOCOLS.contains(&version.as_str()),
                        "unsupported MCP protocol version {version}"
                    );
                }
                if self.source.transport == CapabilityTransport::StreamableHttp {
                    ensure!(
                        self.source.uri.starts_with("https://")
                            || self.source.uri.starts_with("http://127.0.0.1")
                            || self.source.uri.starts_with("http://localhost"),
                        "remote MCP sources require HTTPS; HTTP is allowed only on loopback"
                    );
                }
                if self.source.transport == CapabilityTransport::Stdio {
                    ensure!(
                        self.source
                            .entrypoint
                            .as_deref()
                            .is_some_and(|value| !value.is_empty()),
                        "stdio MCP sources require an entrypoint"
                    );
                    ensure!(
                        self.source.uri.starts_with("file://"),
                        "stdio MCP sources must be local file directories"
                    );
                    let entrypoint = self.source.entrypoint.as_deref().unwrap_or_default();
                    ensure!(
                        !entrypoint.starts_with('/')
                            && !entrypoint.split('/').any(|part| part == ".."),
                        "stdio MCP entrypoint must be package-relative"
                    );
                    ensure!(
                        self.source.environment_keys.is_empty(),
                        "v0.1 stdio MCP sandbox does not accept environment credentials"
                    );
                }
            }
            CapabilityPackageKind::ConcordNative => {
                ensure!(
                    matches!(
                        self.source.transport,
                        CapabilityTransport::Directory | CapabilityTransport::Stdio
                    ),
                    "native packages require a directory or stdio transport"
                );
            }
        }

        let mut selectors = BTreeSet::new();
        for permission in &self.permissions {
            ensure!(
                !permission.selector.trim().is_empty(),
                "permission selector is required"
            );
            ensure!(
                selectors.insert(permission.selector.as_str()),
                "duplicate permission selector {}",
                permission.selector
            );
            if permission.effect != EffectClass::ReadOnly {
                ensure!(
                    permission.approval != ApprovalMode::Never,
                    "effectful tool {} cannot default to never requiring approval",
                    permission.selector
                );
            }
        }
        Ok(())
    }

    /// Resolve only Concord-owned policy. Upstream Agent Skills hints are deliberately ignored.
    pub fn approval_for(&self, tool_name: &str) -> ApprovalMode {
        self.permissions
            .iter()
            .find(|permission| permission.selector == tool_name)
            .or_else(|| {
                self.permissions
                    .iter()
                    .find(|permission| permission.selector == "*")
            })
            .map(|permission| permission.approval.clone())
            .unwrap_or(ApprovalMode::EveryCall)
    }
}

impl McpDiscoverySnapshot {
    pub fn build(
        package_id: String,
        protocol_version: String,
        server_name: String,
        server_version: String,
        discovered_at: String,
        mut tools: Vec<McpToolSnapshot>,
    ) -> Result<Self> {
        tools.sort_by(|left, right| left.name.cmp(&right.name));
        let hash_input = serde_json::json!({
            "contract": MCP_DISCOVERY_CONTRACT,
            "packageId": package_id,
            "protocolVersion": protocol_version,
            "serverName": server_name,
            "serverVersion": server_version,
            "tools": tools,
        });
        let discovery_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&hash_input)?));
        let snapshot = Self {
            contract: MCP_DISCOVERY_CONTRACT.to_owned(),
            package_id: hash_input["packageId"]
                .as_str()
                .context("package id disappeared from MCP discovery hash input")?
                .to_owned(),
            protocol_version: hash_input["protocolVersion"]
                .as_str()
                .context("protocol version disappeared from MCP discovery hash input")?
                .to_owned(),
            server_name: hash_input["serverName"]
                .as_str()
                .context("server name disappeared from MCP discovery hash input")?
                .to_owned(),
            server_version: hash_input["serverVersion"]
                .as_str()
                .context("server version disappeared from MCP discovery hash input")?
                .to_owned(),
            discovered_at,
            tools,
            discovery_sha256,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.contract == MCP_DISCOVERY_CONTRACT,
            "unsupported MCP discovery contract"
        );
        validate_package_id(&self.package_id)?;
        ensure!(
            SUPPORTED_MCP_PROTOCOLS.contains(&self.protocol_version.as_str()),
            "unsupported MCP protocol version {}",
            self.protocol_version
        );
        ensure!(
            !self.server_name.trim().is_empty(),
            "MCP server name is required"
        );
        ensure!(
            !self.server_version.trim().is_empty(),
            "MCP server version is required"
        );
        validate_sha256(&self.discovery_sha256)?;
        let mut names = BTreeSet::new();
        let mut previous_name: Option<&str> = None;
        for tool in &self.tools {
            ensure!(!tool.name.trim().is_empty(), "MCP tool name is required");
            ensure!(
                names.insert(tool.name.as_str()),
                "duplicate MCP tool {}",
                tool.name
            );
            ensure!(
                previous_name.is_none_or(|previous| previous < tool.name.as_str()),
                "MCP tools must be sorted by name"
            );
            previous_name = Some(&tool.name);
            ensure!(
                tool.input_schema.is_object(),
                "MCP tool {} input schema must be an object",
                tool.name
            );
        }
        let hash_input = serde_json::json!({
            "contract": self.contract,
            "packageId": self.package_id,
            "protocolVersion": self.protocol_version,
            "serverName": self.server_name,
            "serverVersion": self.server_version,
            "tools": self.tools,
        });
        let expected = format!("{:x}", Sha256::digest(serde_json::to_vec(&hash_input)?));
        ensure!(
            self.discovery_sha256 == expected,
            "MCP discovery digest mismatch"
        );
        Ok(())
    }
}

pub fn capability_package_record_id(package: &CapabilityPackage) -> Result<String> {
    package.validate()?;
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(package)?));
    Ok(format!("pkg_{}", &digest[..24]))
}

fn validate_package_id(value: &str) -> Result<()> {
    ensure!(
        (1..=128).contains(&value.len()),
        "package id must contain 1-128 characters"
    );
    ensure!(
        value.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'.' | b'/')),
        "package id contains unsupported characters"
    );
    ensure!(
        !value.starts_with(['-', '.', '/']),
        "package id has an invalid prefix"
    );
    ensure!(
        !value.ends_with(['-', '.', '/']),
        "package id has an invalid suffix"
    );
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "SHA-256 values must be 64 hexadecimal characters"
    );
    Ok(())
}

fn valid_environment_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_uppercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn contains_embedded_credential(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    let has_user_info = lower.find("://").is_some_and(|scheme_end| {
        let authority = &lower[scheme_end + 3..];
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        authority.contains('@')
    });
    has_user_info
        || lower.contains("api_key=")
        || lower.contains("access_token=")
        || lower.contains("secret=")
}

fn yaml_frontmatter(contents: &str) -> Result<&str> {
    let mut lines = contents.split_inclusive('\n');
    let first = lines
        .next()
        .unwrap_or_default()
        .trim_end_matches(['\r', '\n']);
    ensure!(first == "---", "SKILL.md must start with YAML frontmatter");
    let start = first.len() + (contents[first.len()..].starts_with("\r\n") as usize) + 1;
    let remainder = &contents[start..];
    let mut offset = 0;
    for line in remainder.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "---" {
            return Ok(&remainder[..offset]);
        }
        offset += line.len();
    }
    anyhow::bail!("SKILL.md frontmatter is not terminated")
}

fn validate_agent_skill_name(value: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&value.len()),
        "Agent Skill name must contain 1-64 characters"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "Agent Skill name must contain only lowercase letters, digits, and hyphens"
    );
    ensure!(
        !value.starts_with('-') && !value.ends_with('-'),
        "Agent Skill name cannot start or end with a hyphen"
    );
    ensure!(
        !value.contains("--"),
        "Agent Skill name cannot contain consecutive hyphens"
    );
    Ok(())
}

fn hash_directory(root: &Path) -> Result<(String, u64, u64)> {
    let mut files = Vec::new();
    collect_regular_files(root, root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    let mut byte_count = 0_u64;
    for relative in &files {
        let path_bytes = relative.to_string_lossy();
        let contents = fs::read(root.join(relative))?;
        byte_count = byte_count
            .checked_add(contents.len() as u64)
            .context("Agent Skill byte count overflow")?;
        ensure!(
            byte_count <= 64 * 1024 * 1024,
            "Agent Skill exceeds the 64 MiB inspection limit"
        );
        hasher.update((path_bytes.len() as u64).to_be_bytes());
        hasher.update(path_bytes.as_bytes());
        hasher.update((contents.len() as u64).to_be_bytes());
        hasher.update(&contents);
    }
    Ok((
        format!("{:x}", hasher.finalize()),
        files.len() as u64,
        byte_count,
    ))
}

pub fn verify_directory_content_sha256(root: &Path, expected: &str) -> Result<()> {
    validate_sha256(expected)?;
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize package directory {}", root.display()))?;
    ensure!(root.is_dir(), "package source must be a directory");
    let (actual, _, _) = hash_directory(&root)?;
    ensure!(
        actual == expected,
        "package directory content changed after registration"
    );
    Ok(())
}

fn collect_regular_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type()?;
        ensure!(
            !file_type.is_symlink(),
            "Agent Skill packages cannot contain symlinks"
        );
        if file_type.is_dir() {
            collect_regular_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            files.push(entry.path().strip_prefix(root)?.to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn skill_package() -> CapabilityPackage {
        CapabilityPackage {
            contract: CAPABILITY_PACKAGE_CONTRACT.to_owned(),
            package_id: "org.example/literature-review".to_owned(),
            display_name: "Literature review".to_owned(),
            version: "1.0.0".to_owned(),
            kind: CapabilityPackageKind::AgentSkill,
            source: CapabilityPackageSource {
                uri: "file:///opt/skills/literature-review".to_owned(),
                transport: CapabilityTransport::Directory,
                entrypoint: Some("SKILL.md".to_owned()),
                arguments: vec![],
                environment_keys: vec![],
                protocol_versions: vec![],
                authentication: CapabilityAuthentication::None,
            },
            content_sha256: "a".repeat(64),
            trust_status: PackageTrustStatus::Inspected,
            declared_capabilities: vec!["literature_review".to_owned()],
            permissions: vec![],
            upstream_allowed_tools: vec!["Bash(curl:*)".to_owned()],
            metadata: json!({"sourceFormat": "agentskills.io/1"}),
        }
    }

    #[test]
    fn accepts_portable_agent_skill_without_a_model_vendor() {
        let package = skill_package();
        package.validate().unwrap();
        let encoded = serde_json::to_string(&package).unwrap();
        assert!(!encoded.contains("modelProvider"));
    }

    #[test]
    fn upstream_allowed_tools_never_bypass_concord_policy() {
        let package = skill_package();
        assert_eq!(package.approval_for("Bash"), ApprovalMode::EveryCall);
    }

    #[test]
    fn accepts_current_and_previous_mcp_protocols() {
        let mut package = skill_package();
        package.package_id = "org.example/scientific-databases".to_owned();
        package.kind = CapabilityPackageKind::McpServer;
        package.source = CapabilityPackageSource {
            uri: "https://mcp.example.org/mcp".to_owned(),
            transport: CapabilityTransport::StreamableHttp,
            entrypoint: None,
            arguments: vec![],
            environment_keys: vec!["EXAMPLE_OAUTH_TOKEN".to_owned()],
            protocol_versions: vec!["2025-11-25".to_owned(), "2026-07-28".to_owned()],
            authentication: CapabilityAuthentication::BearerEnvironment {
                key: "EXAMPLE_OAUTH_TOKEN".to_owned(),
            },
        };
        package.permissions = vec![CapabilityPermission {
            selector: "search".to_owned(),
            effect: EffectClass::NetworkRead,
            approval: ApprovalMode::EveryCall,
            data_classes: vec!["public_literature".to_owned()],
        }];
        package.validate().unwrap();
    }

    #[test]
    fn rejects_effectful_never_approve_policy() {
        let mut package = skill_package();
        package.permissions = vec![CapabilityPermission {
            selector: "submit_job".to_owned(),
            effect: EffectClass::PaidCompute,
            approval: ApprovalMode::Never,
            data_classes: vec![],
        }];
        let error = package.validate().unwrap_err().to_string();
        assert!(error.contains("cannot default to never requiring approval"));
    }

    #[test]
    fn rejects_credentials_in_remote_source_uri() {
        let mut package = skill_package();
        package.kind = CapabilityPackageKind::McpServer;
        package.source.transport = CapabilityTransport::StreamableHttp;
        package.source.uri = "https://mcp.example.org/mcp?access_token=secret".to_owned();
        package.source.entrypoint = None;
        package.source.protocol_versions = vec!["2026-07-28".to_owned()];
        let error = package.validate().unwrap_err().to_string();
        assert!(error.contains("must not embed credentials"));
        package.source.uri = "https://token@example.org/mcp".to_owned();
        let error = package.validate().unwrap_err().to_string();
        assert!(error.contains("must not embed credentials"));
    }

    #[test]
    fn validates_a_frozen_mcp_tool_catalog() {
        let mut snapshot = McpDiscoverySnapshot::build(
            "org.example/scientific-databases".to_owned(),
            "2026-07-28".to_owned(),
            "Scientific databases".to_owned(),
            "2.1.0".to_owned(),
            "2026-08-12T00:00:00Z".to_owned(),
            vec![McpToolSnapshot {
                name: "search".to_owned(),
                description: "Search public scientific databases".to_owned(),
                input_schema: json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}),
                output_schema: None,
            }],
        )
        .unwrap();
        snapshot.validate().unwrap();
        snapshot.tools[0].description = "Altered after discovery".into();
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn qualification_hash_binds_policy_and_rejects_approval_free_effects() {
        let mut qualification = CapabilityQualification::build(
            "cappkg_fixture".into(),
            "a".repeat(64),
            Some("mcpdisc_fixture".into()),
            Some("b".repeat(64)),
            QualificationDisposition::Qualified,
            vec![CapabilityToolPolicy {
                tool_name: "search".into(),
                effect: EffectClass::NetworkRead,
                approval: ApprovalMode::EveryCall,
                data_classes: vec!["public_literature".into()],
                reversibility: ReversibilityPolicy {
                    class: ReversibilityClass::ReadOnly,
                    reversal_action: None,
                    limitations: vec!["The remote source may retain access logs.".into()],
                },
            }],
            "reviewer@example.org".into(),
            "Public literature only; each request requires approval.".into(),
            None,
            "2026-08-13T00:00:00Z".into(),
        )
        .unwrap();
        let mut reversibility_tamper = qualification.clone();
        reversibility_tamper.tool_policies[0]
            .reversibility
            .limitations = vec!["Changed after qualification.".into()];
        assert!(reversibility_tamper.validate().is_err());
        qualification.tool_policies[0].data_classes = vec!["restricted".into()];
        assert!(qualification.validate().is_err());

        assert!(CapabilityQualification::build(
            "cappkg_fixture".into(),
            "a".repeat(64),
            Some("mcpdisc_fixture".into()),
            Some("b".repeat(64)),
            QualificationDisposition::Qualified,
            vec![CapabilityToolPolicy {
                tool_name: "write".into(),
                effect: EffectClass::ExternalWrite,
                approval: ApprovalMode::EveryCall,
                data_classes: vec![],
                reversibility: ReversibilityPolicy {
                    class: ReversibilityClass::ReadOnly,
                    reversal_action: None,
                    limitations: vec![],
                },
            }],
            "reviewer@example.org".into(),
            "A write cannot pretend to be read-only.".into(),
            None,
            "2026-08-13T00:00:00Z".into(),
        )
        .is_err());

        assert!(CapabilityQualification::build(
            "cappkg_fixture".into(),
            "a".repeat(64),
            Some("mcpdisc_fixture".into()),
            Some("b".repeat(64)),
            QualificationDisposition::Qualified,
            vec![CapabilityToolPolicy {
                tool_name: "write".into(),
                effect: EffectClass::ExternalWrite,
                approval: ApprovalMode::Never,
                data_classes: vec![],
                reversibility: ReversibilityPolicy {
                    class: ReversibilityClass::CompensatingAction,
                    reversal_action: Some("Delete or supersede the created remote object.".into()),
                    limitations: vec!["Provider audit logs may remain.".into()],
                },
            }],
            "reviewer@example.org".into(),
            "Unsafe policy should fail.".into(),
            None,
            "2026-08-13T00:00:00Z".into(),
        )
        .is_err());
    }

    #[test]
    fn inspects_a_standard_agent_skill_without_executing_it() {
        let root =
            std::env::temp_dir().join(format!("concord-agent-skill-{}", uuid::Uuid::new_v4()));
        let skill = root.join("literature-review");
        std::fs::create_dir_all(skill.join("scripts")).unwrap();
        std::fs::write(
            skill.join("SKILL.md"),
            "---\nname: literature-review\ndescription: Search and synthesize literature when a scientific question needs primary sources.\nmetadata:\n  version: \"1.2.0\"\nallowed-tools: Read Bash(curl:*)\n---\n\n# Literature review\n",
        )
        .unwrap();
        std::fs::write(
            skill.join("scripts/search.py"),
            "raise SystemExit('must not run during import')\n",
        )
        .unwrap();

        let package = inspect_agent_skill_directory(&skill).unwrap();
        assert_eq!(package.version, "1.2.0");
        assert_eq!(package.trust_status, PackageTrustStatus::Quarantined);
        assert_eq!(package.upstream_allowed_tools, vec!["Read", "Bash(curl:*)"]);
        assert_eq!(package.approval_for("Read"), ApprovalMode::EveryCall);
        assert_eq!(package.metadata["fileCount"], 2);

        std::fs::remove_dir_all(root).unwrap();
    }
}
