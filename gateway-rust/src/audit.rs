// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The ONE writer for `noo_security_audit`, and the vocabulary call sites use
//! to say what happened.
//!
//! A call site names an [`AuditKind`] (which owns the wire string written to
//! `event_type` and the default severity), an actor, a resource and an
//! [`Outcome`], and hands an [`AuditEvent`] to [`record`] (best-effort) or
//! [`record_required`] (the caller must know the row landed). It used to be
//! five adjacent `&str` parameters, where swapping two compiled; now the
//! event type, the severity and the outcome are three different types.
//!
//! This module changes how call sites SAY what happened, not the row: the
//! columns written, the HMAC signing (`audit_integrity`), the chain
//! (`audit_chain`) and the origin stamp (`audit_context::with_origin`) are
//! exactly what they were. The wire string of every kind is the string the
//! call sites wrote before, pinned by the test at the bottom, so existing
//! rows, alerts and `noo security audit` filters keep matching.

use std::borrow::Cow;

use serde_json::{json, Value};

/// How loud a row is. The wire strings are what `noo_security_audit.severity`
/// holds; `Error` exists because one writer (the entity-cleanup run) records
/// a failed destructive run at that level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// The severity a wire string names, if it names one.
    pub(crate) fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Self::Info,
            "warning" => Self::Warning,
            "error" => Self::Error,
            "critical" => Self::Critical,
            _ => return None,
        })
    }
}

/// What happened to the thing the row is about. `Ok`, `Denied` and `Error`
/// are the common three; everything else a site writes today
/// (`started`, `refused`, `queued_spool`, `pending`, ...) is `Custom`, with
/// the exact wire string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Ok,
    Denied,
    Error,
    Custom(Cow<'static, str>),
}

impl Outcome {
    /// A fixed outcome word, e.g. `Outcome::custom("started")`.
    pub(crate) const fn custom(s: &'static str) -> Self {
        Self::Custom(Cow::Borrowed(s))
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Error => "error",
            Self::Custom(s) => s.as_ref(),
        }
    }
}

/// An outcome computed at run time (a decision, a status read from a row).
/// The three common words map onto their variants; anything else is `Custom`.
impl From<&str> for Outcome {
    fn from(s: &str) -> Self {
        match s {
            "ok" => Self::Ok,
            "denied" => Self::Denied,
            "error" => Self::Error,
            other => Self::Custom(Cow::Owned(other.to_string())),
        }
    }
}

impl From<&String> for Outcome {
    fn from(s: &String) -> Self {
        Self::from(s.as_str())
    }
}

impl From<String> for Outcome {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

/// Every kind of row the gateway writes. One variant per `event_type` string;
/// `as_str` is that string, EXACTLY as the call sites wrote it before this
/// type existed.
///
/// `Other` keeps a raw string for the deprecated string shims in
/// `routes::core` (an add-on, or a site that was missed, still writes a row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditKind {
    AddonAccessSet,
    AgentArchiveDecrypt,
    AgentKeyRegistered,
    ApprovalDecision,
    AuditLogRead,
    AuthFailure, // also critical at some sites
    AuthLogout,
    AuthSuccess,
    BootstrapTokenCreate,
    BootstrapTokenDenied,
    BootstrapTokenRevoke,
    BootstrapTokenUsed,
    BundleApplyReported, // also warning at some sites
    ChannelIngressDenied,
    CliAssetUploaded,
    ConfigUpdate,
    ConfigUpdateRefused,
    DataDelete,
    DeleteTailscaleDevice,
    EmbeddingMigrationCancelled,
    EmbeddingMigrationCutover,
    EmbeddingMigrationStarted,
    EmbeddingSpaceDeclared,
    EmbeddingSpaceRemoved,
    EnrollNameConflict,
    ErasureArchivePurge,
    ExecApprovalDecided, // also warning at some sites
    ExecApprovalRequested,
    ExecDenied,
    GrafanaSessionIssued,
    GraphEntityCleanup, // also error at some sites
    IdentityTokenIssue,
    JobCancel,
    JobCancelDenied,
    JobSubmit, // also warning at some sites
    KbHold, // also warning at some sites
    KbPurge,
    KbRetag, // also warning at some sites
    KbRolesGrant,
    KbRolesRevoke,
    KbRuleSet,
    KbTeamCreate,
    KbTeamDelete,
    KbUnhold, // also warning at some sites
    KioskTailnetMintDenied,
    McpExternalCall,
    McpServerPlace,
    McpServerRegister,
    McpServerRemove,
    McpServerUnplace,
    McpServerUpdate,
    McpToolCall,
    MeshRebuild,
    MeshRestart,
    MintJoinKey,
    ModelAliasDeclared,
    ModelAliasRemoved,
    ModelClassDeclared,
    ModelClassRemoved,
    NodeBench,
    NodeForgotten,
    NodeGpuHold,
    NodeGpuRelease,
    OperatorCertRegistered,
    OperatorCertRevoked,
    OrgCreate,
    PeerDeregistered,
    PeerTokenMinted,
    PromptSkillPromoted,
    PromptSkillRejected,
    ProvisionBundleStaged,
    ReservationRelease,
    ReservationTake,
    SeatBundleApplied, // also warning at some sites
    SeatBundleStaged,
    SeatEnrolled,
    SeatTokenCreate,
    SeatTokenDenied,
    SeatTokenRevoke,
    SecurityPostureProfile,
    SecurityPostureRetiredRowRemoved,
    SecurityPostureSet,
    ServiceKeyIssue,
    ServiceKeyRetire,
    ServiceKeyRevoke,
    ServiceKeyRevokeAndDisable,
    ServiceKeyRotate,
    ServiceKeySelfIssue,
    ServiceKeySelfRevoke,
    ServiceKeySetQuota,
    SettingFlagSet,
    StackRebuild,
    SuperAdminSet,
    TailnetEnrollAdmitted,
    TailnetEnrollDenied,
    TaskAnswered,
    TaskCreated,
    TaskResubmitted,
    TaskStopped,
    TeamSpaceLink,
    TeamSpaceUnlink,
    TokenAllowanceRemoved,
    TokenAllowanceSet,
    ToolExec, // also warning at some sites
    UserChannelLink,
    UserChannelUnlink,
    UserCreate,
    UserErase,
    UserEraseRefused,
    UserProposalApproved,
    UserProposalDenied,
    UserProposalFailed,
    UserProposalFiled,
    UserSetDisabled,
    UserSetOrg,
    UserSetPassword,
    UserSetRole,
    UserSetScopes,
    WalksAdminView,
    /// A string with no variant (only reachable through the deprecated
    /// `routes::core::audit_event` shims).
    Other(String),
}

impl AuditKind {
    /// The `event_type` column value.
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::AddonAccessSet => "addon_access_set",
            Self::AgentArchiveDecrypt => "agent_archive_decrypt",
            Self::AgentKeyRegistered => "agent_key_registered",
            Self::ApprovalDecision => "approval_decision",
            Self::AuditLogRead => "audit_log_read",
            Self::AuthFailure => "auth_failure",
            Self::AuthLogout => "auth_logout",
            Self::AuthSuccess => "auth_success",
            Self::BootstrapTokenCreate => "bootstrap_token_create",
            Self::BootstrapTokenDenied => "bootstrap_token_denied",
            Self::BootstrapTokenRevoke => "bootstrap_token_revoke",
            Self::BootstrapTokenUsed => "bootstrap_token_used",
            Self::BundleApplyReported => "bundle_apply_reported",
            Self::ChannelIngressDenied => "channel_ingress_denied",
            Self::CliAssetUploaded => "cli_asset_uploaded",
            Self::ConfigUpdate => "config_update",
            Self::ConfigUpdateRefused => "config_update_refused",
            Self::DataDelete => "data_delete",
            Self::DeleteTailscaleDevice => "delete_tailscale_device",
            Self::EmbeddingMigrationCancelled => "embedding_migration_cancelled",
            Self::EmbeddingMigrationCutover => "embedding_migration_cutover",
            Self::EmbeddingMigrationStarted => "embedding_migration_started",
            Self::EmbeddingSpaceDeclared => "embedding_space_declared",
            Self::EmbeddingSpaceRemoved => "embedding_space_removed",
            Self::EnrollNameConflict => "enroll_name_conflict",
            Self::ErasureArchivePurge => "erasure_archive_purge",
            Self::ExecApprovalDecided => "exec_approval_decided",
            Self::ExecApprovalRequested => "exec_approval_requested",
            Self::ExecDenied => "exec_denied",
            Self::GrafanaSessionIssued => "grafana_session_issued",
            Self::GraphEntityCleanup => "graph_entity_cleanup",
            Self::IdentityTokenIssue => "identity_token_issue",
            Self::JobCancel => "job_cancel",
            Self::JobCancelDenied => "job_cancel_denied",
            Self::JobSubmit => "job_submit",
            Self::KbHold => "kb_hold",
            Self::KbPurge => "kb_purge",
            Self::KbRetag => "kb_retag",
            Self::KbRolesGrant => "kb_roles_grant",
            Self::KbRolesRevoke => "kb_roles_revoke",
            Self::KbRuleSet => "kb_rule_set",
            Self::KbTeamCreate => "kb_team_create",
            Self::KbTeamDelete => "kb_team_delete",
            Self::KbUnhold => "kb_unhold",
            Self::KioskTailnetMintDenied => "kiosk_tailnet_mint_denied",
            Self::McpExternalCall => "mcp_external_call",
            Self::McpServerPlace => "mcp_server_place",
            Self::McpServerRegister => "mcp_server_register",
            Self::McpServerRemove => "mcp_server_remove",
            Self::McpServerUnplace => "mcp_server_unplace",
            Self::McpServerUpdate => "mcp_server_update",
            Self::McpToolCall => "mcp_tool_call",
            Self::MeshRebuild => "mesh_rebuild",
            Self::MeshRestart => "mesh_restart",
            Self::MintJoinKey => "mint_join_key",
            Self::ModelAliasDeclared => "model_alias_declared",
            Self::ModelAliasRemoved => "model_alias_removed",
            Self::ModelClassDeclared => "model_class_declared",
            Self::ModelClassRemoved => "model_class_removed",
            Self::NodeBench => "node_bench",
            Self::NodeForgotten => "node_forgotten",
            Self::NodeGpuHold => "node_gpu_hold",
            Self::NodeGpuRelease => "node_gpu_release",
            Self::OperatorCertRegistered => "operator_cert_registered",
            Self::OperatorCertRevoked => "operator_cert_revoked",
            Self::OrgCreate => "org_create",
            Self::PeerDeregistered => "peer_deregistered",
            Self::PeerTokenMinted => "peer_token_minted",
            Self::PromptSkillPromoted => "prompt_skill_promoted",
            Self::PromptSkillRejected => "prompt_skill_rejected",
            Self::ProvisionBundleStaged => "provision_bundle_staged",
            Self::ReservationRelease => "reservation_release",
            Self::ReservationTake => "reservation_take",
            Self::SeatBundleApplied => "seat_bundle_applied",
            Self::SeatBundleStaged => "seat_bundle_staged",
            Self::SeatEnrolled => "seat_enrolled",
            Self::SeatTokenCreate => "seat_token_create",
            Self::SeatTokenDenied => "seat_token_denied",
            Self::SeatTokenRevoke => "seat_token_revoke",
            Self::SecurityPostureProfile => "security_posture_profile",
            Self::SecurityPostureRetiredRowRemoved => "security_posture_retired_row_removed",
            Self::SecurityPostureSet => "security_posture_set",
            Self::ServiceKeyIssue => "service_key_issue",
            Self::ServiceKeyRetire => "service_key_retire",
            Self::ServiceKeyRevoke => "service_key_revoke",
            Self::ServiceKeyRevokeAndDisable => "service_key_revoke_and_disable",
            Self::ServiceKeyRotate => "service_key_rotate",
            Self::ServiceKeySelfIssue => "service_key_self_issue",
            Self::ServiceKeySelfRevoke => "service_key_self_revoke",
            Self::ServiceKeySetQuota => "service_key_set_quota",
            Self::SettingFlagSet => "setting_flag_set",
            Self::StackRebuild => "stack_rebuild",
            Self::SuperAdminSet => "super_admin_set",
            Self::TailnetEnrollAdmitted => "tailnet_enroll_admitted",
            Self::TailnetEnrollDenied => "tailnet_enroll_denied",
            Self::TaskAnswered => "task_answered",
            Self::TaskCreated => "task_created",
            Self::TaskResubmitted => "task_resubmitted",
            Self::TaskStopped => "task_stopped",
            Self::TeamSpaceLink => "team_space_link",
            Self::TeamSpaceUnlink => "team_space_unlink",
            Self::TokenAllowanceRemoved => "token_allowance_removed",
            Self::TokenAllowanceSet => "token_allowance_set",
            Self::ToolExec => "tool_exec",
            Self::UserChannelLink => "user_channel_link",
            Self::UserChannelUnlink => "user_channel_unlink",
            Self::UserCreate => "user_create",
            Self::UserErase => "user_erase",
            Self::UserEraseRefused => "user_erase_refused",
            Self::UserProposalApproved => "user_proposal_approved",
            Self::UserProposalDenied => "user_proposal_denied",
            Self::UserProposalFailed => "user_proposal_failed",
            Self::UserProposalFiled => "user_proposal_filed",
            Self::UserSetDisabled => "user_set_disabled",
            Self::UserSetOrg => "user_set_org",
            Self::UserSetPassword => "user_set_password",
            Self::UserSetRole => "user_set_role",
            Self::UserSetScopes => "user_set_scopes",
            Self::WalksAdminView => "walks_admin_view",
            Self::Other(s) => s,
        }
    }

    /// The severity a row of this kind carries unless the site overrides it.
    /// Where one kind is written at two severities today, this is the lower
    /// one and the site that wanted higher says so with
    /// [`AuditEvent::severity`].
    pub(crate) fn default_severity(&self) -> Severity {
        match self {
            Self::AddonAccessSet => Severity::Info,
            Self::AgentArchiveDecrypt => Severity::Warning,
            Self::AgentKeyRegistered => Severity::Info,
            Self::ApprovalDecision => Severity::Info,
            Self::AuditLogRead => Severity::Info,
            Self::AuthFailure => Severity::Warning,
            Self::AuthLogout => Severity::Info,
            Self::AuthSuccess => Severity::Info,
            Self::BootstrapTokenCreate => Severity::Warning,
            Self::BootstrapTokenDenied => Severity::Warning,
            Self::BootstrapTokenRevoke => Severity::Info,
            Self::BootstrapTokenUsed => Severity::Warning,
            Self::BundleApplyReported => Severity::Info,
            Self::ChannelIngressDenied => Severity::Warning,
            Self::CliAssetUploaded => Severity::Warning,
            Self::ConfigUpdate => Severity::Warning,
            Self::ConfigUpdateRefused => Severity::Warning,
            Self::DataDelete => Severity::Warning,
            Self::DeleteTailscaleDevice => Severity::Warning,
            Self::EmbeddingMigrationCancelled => Severity::Info,
            Self::EmbeddingMigrationCutover => Severity::Info,
            Self::EmbeddingMigrationStarted => Severity::Info,
            Self::EmbeddingSpaceDeclared => Severity::Info,
            Self::EmbeddingSpaceRemoved => Severity::Info,
            Self::EnrollNameConflict => Severity::Warning,
            Self::ErasureArchivePurge => Severity::Info,
            Self::ExecApprovalDecided => Severity::Info,
            Self::ExecApprovalRequested => Severity::Warning,
            Self::ExecDenied => Severity::Warning,
            Self::GrafanaSessionIssued => Severity::Info,
            Self::GraphEntityCleanup => Severity::Warning,
            Self::IdentityTokenIssue => Severity::Info,
            Self::JobCancel => Severity::Info,
            Self::JobCancelDenied => Severity::Warning,
            Self::JobSubmit => Severity::Info,
            Self::KbHold => Severity::Info,
            Self::KbPurge => Severity::Warning,
            Self::KbRetag => Severity::Info,
            Self::KbRolesGrant => Severity::Info,
            Self::KbRolesRevoke => Severity::Info,
            Self::KbRuleSet => Severity::Info,
            Self::KbTeamCreate => Severity::Info,
            Self::KbTeamDelete => Severity::Info,
            Self::KbUnhold => Severity::Info,
            Self::KioskTailnetMintDenied => Severity::Warning,
            Self::McpExternalCall => Severity::Info,
            Self::McpServerPlace => Severity::Info,
            Self::McpServerRegister => Severity::Info,
            Self::McpServerRemove => Severity::Info,
            Self::McpServerUnplace => Severity::Info,
            Self::McpServerUpdate => Severity::Info,
            Self::McpToolCall => Severity::Info,
            Self::MeshRebuild => Severity::Warning,
            Self::MeshRestart => Severity::Warning,
            Self::MintJoinKey => Severity::Warning,
            Self::ModelAliasDeclared => Severity::Info,
            Self::ModelAliasRemoved => Severity::Info,
            Self::ModelClassDeclared => Severity::Info,
            Self::ModelClassRemoved => Severity::Info,
            Self::NodeBench => Severity::Info,
            Self::NodeForgotten => Severity::Warning,
            Self::NodeGpuHold => Severity::Info,
            Self::NodeGpuRelease => Severity::Info,
            Self::OperatorCertRegistered => Severity::Warning,
            Self::OperatorCertRevoked => Severity::Warning,
            Self::OrgCreate => Severity::Info,
            Self::PeerDeregistered => Severity::Info,
            Self::PeerTokenMinted => Severity::Info,
            Self::PromptSkillPromoted => Severity::Info,
            Self::PromptSkillRejected => Severity::Info,
            Self::ProvisionBundleStaged => Severity::Warning,
            Self::ReservationRelease => Severity::Info,
            Self::ReservationTake => Severity::Info,
            Self::SeatBundleApplied => Severity::Info,
            Self::SeatBundleStaged => Severity::Warning,
            Self::SeatEnrolled => Severity::Warning,
            Self::SeatTokenCreate => Severity::Warning,
            Self::SeatTokenDenied => Severity::Warning,
            Self::SeatTokenRevoke => Severity::Info,
            Self::SecurityPostureProfile => Severity::Warning,
            Self::SecurityPostureRetiredRowRemoved => Severity::Info,
            Self::SecurityPostureSet => Severity::Warning,
            Self::ServiceKeyIssue => Severity::Info,
            Self::ServiceKeyRetire => Severity::Info,
            Self::ServiceKeyRevoke => Severity::Info,
            Self::ServiceKeyRevokeAndDisable => Severity::Warning,
            Self::ServiceKeyRotate => Severity::Info,
            Self::ServiceKeySelfIssue => Severity::Info,
            Self::ServiceKeySelfRevoke => Severity::Info,
            Self::ServiceKeySetQuota => Severity::Info,
            Self::SettingFlagSet => Severity::Info,
            Self::StackRebuild => Severity::Warning,
            Self::SuperAdminSet => Severity::Warning,
            Self::TailnetEnrollAdmitted => Severity::Warning,
            Self::TailnetEnrollDenied => Severity::Warning,
            Self::TaskAnswered => Severity::Info,
            Self::TaskCreated => Severity::Info,
            Self::TaskResubmitted => Severity::Info,
            Self::TaskStopped => Severity::Info,
            Self::TeamSpaceLink => Severity::Info,
            Self::TeamSpaceUnlink => Severity::Info,
            Self::TokenAllowanceRemoved => Severity::Info,
            Self::TokenAllowanceSet => Severity::Info,
            Self::ToolExec => Severity::Info,
            Self::UserChannelLink => Severity::Info,
            Self::UserChannelUnlink => Severity::Info,
            Self::UserCreate => Severity::Info,
            Self::UserErase => Severity::Warning,
            Self::UserEraseRefused => Severity::Warning,
            Self::UserProposalApproved => Severity::Info,
            Self::UserProposalDenied => Severity::Info,
            Self::UserProposalFailed => Severity::Warning,
            Self::UserProposalFiled => Severity::Info,
            Self::UserSetDisabled => Severity::Info,
            Self::UserSetOrg => Severity::Info,
            Self::UserSetPassword => Severity::Info,
            Self::UserSetRole => Severity::Info,
            Self::UserSetScopes => Severity::Info,
            Self::WalksAdminView => Severity::Warning,
            Self::Other(_) => Severity::Info,
        }
    }

    /// The kind a wire string names; an unknown string is `Other`.
    pub(crate) fn from_wire(s: &str) -> Self {
        match s {
            "addon_access_set" => Self::AddonAccessSet,
            "agent_archive_decrypt" => Self::AgentArchiveDecrypt,
            "agent_key_registered" => Self::AgentKeyRegistered,
            "approval_decision" => Self::ApprovalDecision,
            "audit_log_read" => Self::AuditLogRead,
            "auth_failure" => Self::AuthFailure,
            "auth_logout" => Self::AuthLogout,
            "auth_success" => Self::AuthSuccess,
            "bootstrap_token_create" => Self::BootstrapTokenCreate,
            "bootstrap_token_denied" => Self::BootstrapTokenDenied,
            "bootstrap_token_revoke" => Self::BootstrapTokenRevoke,
            "bootstrap_token_used" => Self::BootstrapTokenUsed,
            "bundle_apply_reported" => Self::BundleApplyReported,
            "channel_ingress_denied" => Self::ChannelIngressDenied,
            "cli_asset_uploaded" => Self::CliAssetUploaded,
            "config_update" => Self::ConfigUpdate,
            "config_update_refused" => Self::ConfigUpdateRefused,
            "data_delete" => Self::DataDelete,
            "delete_tailscale_device" => Self::DeleteTailscaleDevice,
            "embedding_migration_cancelled" => Self::EmbeddingMigrationCancelled,
            "embedding_migration_cutover" => Self::EmbeddingMigrationCutover,
            "embedding_migration_started" => Self::EmbeddingMigrationStarted,
            "embedding_space_declared" => Self::EmbeddingSpaceDeclared,
            "embedding_space_removed" => Self::EmbeddingSpaceRemoved,
            "enroll_name_conflict" => Self::EnrollNameConflict,
            "erasure_archive_purge" => Self::ErasureArchivePurge,
            "exec_approval_decided" => Self::ExecApprovalDecided,
            "exec_approval_requested" => Self::ExecApprovalRequested,
            "exec_denied" => Self::ExecDenied,
            "grafana_session_issued" => Self::GrafanaSessionIssued,
            "graph_entity_cleanup" => Self::GraphEntityCleanup,
            "identity_token_issue" => Self::IdentityTokenIssue,
            "job_cancel" => Self::JobCancel,
            "job_cancel_denied" => Self::JobCancelDenied,
            "job_submit" => Self::JobSubmit,
            "kb_hold" => Self::KbHold,
            "kb_purge" => Self::KbPurge,
            "kb_retag" => Self::KbRetag,
            "kb_roles_grant" => Self::KbRolesGrant,
            "kb_roles_revoke" => Self::KbRolesRevoke,
            "kb_rule_set" => Self::KbRuleSet,
            "kb_team_create" => Self::KbTeamCreate,
            "kb_team_delete" => Self::KbTeamDelete,
            "kb_unhold" => Self::KbUnhold,
            "kiosk_tailnet_mint_denied" => Self::KioskTailnetMintDenied,
            "mcp_external_call" => Self::McpExternalCall,
            "mcp_server_place" => Self::McpServerPlace,
            "mcp_server_register" => Self::McpServerRegister,
            "mcp_server_remove" => Self::McpServerRemove,
            "mcp_server_unplace" => Self::McpServerUnplace,
            "mcp_server_update" => Self::McpServerUpdate,
            "mcp_tool_call" => Self::McpToolCall,
            "mesh_rebuild" => Self::MeshRebuild,
            "mesh_restart" => Self::MeshRestart,
            "mint_join_key" => Self::MintJoinKey,
            "model_alias_declared" => Self::ModelAliasDeclared,
            "model_alias_removed" => Self::ModelAliasRemoved,
            "model_class_declared" => Self::ModelClassDeclared,
            "model_class_removed" => Self::ModelClassRemoved,
            "node_bench" => Self::NodeBench,
            "node_forgotten" => Self::NodeForgotten,
            "node_gpu_hold" => Self::NodeGpuHold,
            "node_gpu_release" => Self::NodeGpuRelease,
            "operator_cert_registered" => Self::OperatorCertRegistered,
            "operator_cert_revoked" => Self::OperatorCertRevoked,
            "org_create" => Self::OrgCreate,
            "peer_deregistered" => Self::PeerDeregistered,
            "peer_token_minted" => Self::PeerTokenMinted,
            "prompt_skill_promoted" => Self::PromptSkillPromoted,
            "prompt_skill_rejected" => Self::PromptSkillRejected,
            "provision_bundle_staged" => Self::ProvisionBundleStaged,
            "reservation_release" => Self::ReservationRelease,
            "reservation_take" => Self::ReservationTake,
            "seat_bundle_applied" => Self::SeatBundleApplied,
            "seat_bundle_staged" => Self::SeatBundleStaged,
            "seat_enrolled" => Self::SeatEnrolled,
            "seat_token_create" => Self::SeatTokenCreate,
            "seat_token_denied" => Self::SeatTokenDenied,
            "seat_token_revoke" => Self::SeatTokenRevoke,
            "security_posture_profile" => Self::SecurityPostureProfile,
            "security_posture_retired_row_removed" => Self::SecurityPostureRetiredRowRemoved,
            "security_posture_set" => Self::SecurityPostureSet,
            "service_key_issue" => Self::ServiceKeyIssue,
            "service_key_retire" => Self::ServiceKeyRetire,
            "service_key_revoke" => Self::ServiceKeyRevoke,
            "service_key_revoke_and_disable" => Self::ServiceKeyRevokeAndDisable,
            "service_key_rotate" => Self::ServiceKeyRotate,
            "service_key_self_issue" => Self::ServiceKeySelfIssue,
            "service_key_self_revoke" => Self::ServiceKeySelfRevoke,
            "service_key_set_quota" => Self::ServiceKeySetQuota,
            "setting_flag_set" => Self::SettingFlagSet,
            "stack_rebuild" => Self::StackRebuild,
            "super_admin_set" => Self::SuperAdminSet,
            "tailnet_enroll_admitted" => Self::TailnetEnrollAdmitted,
            "tailnet_enroll_denied" => Self::TailnetEnrollDenied,
            "task_answered" => Self::TaskAnswered,
            "task_created" => Self::TaskCreated,
            "task_resubmitted" => Self::TaskResubmitted,
            "task_stopped" => Self::TaskStopped,
            "team_space_link" => Self::TeamSpaceLink,
            "team_space_unlink" => Self::TeamSpaceUnlink,
            "token_allowance_removed" => Self::TokenAllowanceRemoved,
            "token_allowance_set" => Self::TokenAllowanceSet,
            "tool_exec" => Self::ToolExec,
            "user_channel_link" => Self::UserChannelLink,
            "user_channel_unlink" => Self::UserChannelUnlink,
            "user_create" => Self::UserCreate,
            "user_erase" => Self::UserErase,
            "user_erase_refused" => Self::UserEraseRefused,
            "user_proposal_approved" => Self::UserProposalApproved,
            "user_proposal_denied" => Self::UserProposalDenied,
            "user_proposal_failed" => Self::UserProposalFailed,
            "user_proposal_filed" => Self::UserProposalFiled,
            "user_set_disabled" => Self::UserSetDisabled,
            "user_set_org" => Self::UserSetOrg,
            "user_set_password" => Self::UserSetPassword,
            "user_set_role" => Self::UserSetRole,
            "user_set_scopes" => Self::UserSetScopes,
            "walks_admin_view" => Self::WalksAdminView,
            other => Self::Other(other.to_string()),
        }
    }

    /// Every named kind (not `Other`).
    #[cfg(test)]
    fn known() -> Vec<Self> {
        vec![
            Self::AddonAccessSet,
            Self::AgentArchiveDecrypt,
            Self::AgentKeyRegistered,
            Self::ApprovalDecision,
            Self::AuditLogRead,
            Self::AuthFailure,
            Self::AuthLogout,
            Self::AuthSuccess,
            Self::BootstrapTokenCreate,
            Self::BootstrapTokenDenied,
            Self::BootstrapTokenRevoke,
            Self::BootstrapTokenUsed,
            Self::BundleApplyReported,
            Self::ChannelIngressDenied,
            Self::CliAssetUploaded,
            Self::ConfigUpdate,
            Self::ConfigUpdateRefused,
            Self::DataDelete,
            Self::DeleteTailscaleDevice,
            Self::EmbeddingMigrationCancelled,
            Self::EmbeddingMigrationCutover,
            Self::EmbeddingMigrationStarted,
            Self::EmbeddingSpaceDeclared,
            Self::EmbeddingSpaceRemoved,
            Self::EnrollNameConflict,
            Self::ErasureArchivePurge,
            Self::ExecApprovalDecided,
            Self::ExecApprovalRequested,
            Self::ExecDenied,
            Self::GrafanaSessionIssued,
            Self::GraphEntityCleanup,
            Self::IdentityTokenIssue,
            Self::JobCancel,
            Self::JobCancelDenied,
            Self::JobSubmit,
            Self::KbHold,
            Self::KbPurge,
            Self::KbRetag,
            Self::KbRolesGrant,
            Self::KbRolesRevoke,
            Self::KbRuleSet,
            Self::KbTeamCreate,
            Self::KbTeamDelete,
            Self::KbUnhold,
            Self::KioskTailnetMintDenied,
            Self::McpExternalCall,
            Self::McpServerPlace,
            Self::McpServerRegister,
            Self::McpServerRemove,
            Self::McpServerUnplace,
            Self::McpServerUpdate,
            Self::McpToolCall,
            Self::MeshRebuild,
            Self::MeshRestart,
            Self::MintJoinKey,
            Self::ModelAliasDeclared,
            Self::ModelAliasRemoved,
            Self::ModelClassDeclared,
            Self::ModelClassRemoved,
            Self::NodeBench,
            Self::NodeForgotten,
            Self::NodeGpuHold,
            Self::NodeGpuRelease,
            Self::OperatorCertRegistered,
            Self::OperatorCertRevoked,
            Self::OrgCreate,
            Self::PeerDeregistered,
            Self::PeerTokenMinted,
            Self::PromptSkillPromoted,
            Self::PromptSkillRejected,
            Self::ProvisionBundleStaged,
            Self::ReservationRelease,
            Self::ReservationTake,
            Self::SeatBundleApplied,
            Self::SeatBundleStaged,
            Self::SeatEnrolled,
            Self::SeatTokenCreate,
            Self::SeatTokenDenied,
            Self::SeatTokenRevoke,
            Self::SecurityPostureProfile,
            Self::SecurityPostureRetiredRowRemoved,
            Self::SecurityPostureSet,
            Self::ServiceKeyIssue,
            Self::ServiceKeyRetire,
            Self::ServiceKeyRevoke,
            Self::ServiceKeyRevokeAndDisable,
            Self::ServiceKeyRotate,
            Self::ServiceKeySelfIssue,
            Self::ServiceKeySelfRevoke,
            Self::ServiceKeySetQuota,
            Self::SettingFlagSet,
            Self::StackRebuild,
            Self::SuperAdminSet,
            Self::TailnetEnrollAdmitted,
            Self::TailnetEnrollDenied,
            Self::TaskAnswered,
            Self::TaskCreated,
            Self::TaskResubmitted,
            Self::TaskStopped,
            Self::TeamSpaceLink,
            Self::TeamSpaceUnlink,
            Self::TokenAllowanceRemoved,
            Self::TokenAllowanceSet,
            Self::ToolExec,
            Self::UserChannelLink,
            Self::UserChannelUnlink,
            Self::UserCreate,
            Self::UserErase,
            Self::UserEraseRefused,
            Self::UserProposalApproved,
            Self::UserProposalDenied,
            Self::UserProposalFailed,
            Self::UserProposalFiled,
            Self::UserSetDisabled,
            Self::UserSetOrg,
            Self::UserSetPassword,
            Self::UserSetRole,
            Self::UserSetScopes,
            Self::WalksAdminView,
        ]
    }
}

/// One row to write. Build with [`AuditEvent::new`] and the chained setters.
#[derive(Debug, Clone)]
pub(crate) struct AuditEvent {
    kind: AuditKind,
    actor: String,
    resource: String,
    outcome: Outcome,
    details: Value,
    severity: Option<Severity>,
}

impl AuditEvent {
    /// A row of `kind` by `actor` about `resource`: outcome `Ok`, no details,
    /// the kind's default severity.
    pub(crate) fn new(kind: AuditKind, actor: &str, resource: &str) -> Self {
        Self {
            kind,
            actor: actor.to_owned(),
            resource: resource.to_owned(),
            outcome: Outcome::Ok,
            details: json!({}),
            severity: None,
        }
    }

    pub(crate) fn outcome(mut self, outcome: impl Into<Outcome>) -> Self {
        self.outcome = outcome.into();
        self
    }

    pub(crate) fn details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    /// Override the kind's default severity for this row.
    pub(crate) fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// The severity this row is written with: the explicit one, else the
    /// kind's default. A failed login is a warning, and a refresh-token
    /// replay is critical (every auth row used to be `info`, so a failure was
    /// indistinguishable from a success and could not drive alerting).
    pub(crate) fn resolved_severity(&self) -> Severity {
        if let Some(s) = self.severity {
            return s;
        }
        match (&self.kind, &self.outcome) {
            (AuditKind::AuthFailure, o) if o.as_str() == "refresh_replay" => Severity::Critical,
            _ => self.kind.default_severity(),
        }
    }
}

/// General best-effort security-audit insert for privileged actions (config
/// changes, deletions). Never blocks/fails the caller's request. (H-L1)
///
/// The row also records `source_ip` (the request's caller, same trusted-proxy
/// rule as the login rows) and `conversation_id` (inside an agent turn) when
/// known and not already in `details` — see `audit_context`.
pub(crate) async fn record(db: &sqlx::PgPool, ev: AuditEvent) {
    let severity = ev.resolved_severity();
    let AuditEvent { kind, actor, resource, outcome, details, .. } = ev;
    audit_insert(
        db,
        kind.as_str(),
        severity.as_str(),
        &actor,
        &resource,
        outcome.as_str(),
        &crate::audit_context::with_origin(details).to_string(),
    )
    .await;
}

/// [`record`] for a read that must NOT happen unaudited (the admin walks view,
/// the entity-cleanup run): the same signed row through the same writer, but
/// it says whether the row landed, and the caller refuses to proceed when it
/// did not. Everything else stays best-effort through [`record`].
pub(crate) async fn record_required(db: &sqlx::PgPool, ev: AuditEvent) -> bool {
    let severity = ev.resolved_severity();
    let AuditEvent { kind, actor, resource, outcome, details, .. } = ev;
    let event_type = kind.as_str();
    let actor = actor.as_str();
    let Some(key) = crate::audit_integrity::current_key() else {
        tracing::error!(
            event_type, actor,
            "audit_write_refused_no_key: NOO_AUDIT_HMAC_KEY is not set; a view that requires an \
             audit row was refused"
        );
        return false;
    };
    write_audit_row(
        db, &key, event_type, severity.as_str(), actor, &resource,
        outcome.as_str(),
        &crate::audit_context::with_origin(details).to_string(), None,
    )
    .await
}

/// [`record`] for the login rows (`routes::core::audit_auth`): they carry
/// their own `{source_ip}` details and have never gone through
/// `audit_context::with_origin`, so this writes `details` as given.
pub(crate) async fn record_as_given(db: &sqlx::PgPool, ev: AuditEvent) {
    let severity = ev.resolved_severity();
    let AuditEvent { kind, actor, resource, outcome, details, .. } = ev;
    audit_insert(
        db,
        kind.as_str(),
        severity.as_str(),
        &actor,
        &resource,
        outcome.as_str(),
        &details.to_string(),
    )
    .await;
}

/// The ONE writer for `noo_security_audit`, with the missing-partition heal.
///
/// `noo_security_audit` is RANGE-partitioned by month, and an insert with no
/// partition for its timestamp fails outright — Postgres does not create one.
/// Both call sites used to be `let _ = sqlx::query(...)`, so that failure was
/// discarded without a word.
///
/// That is how the audit log died silently on every fresh install.
/// `audit_partition::ensure_current_and_next` runs at startup and asked for
/// `public.noo_ensure_audit_partition`, but a fresh install puts the whole
/// mesh schema in `mesh`, so the function was not found, the error was
/// swallowed as a startup `warn`, no partition was ever created — and then
/// every audit write here was swallowed too. Two layers of silence over a
/// security log, and the only visible symptom was an empty table.
///
/// So this function does three things the old one did not:
///   - heals a missing partition and retries ONCE, the same shape
///     `usage::record` already uses for `noo_token_usage` (which got this
///     right, unqualified call and all);
///   - covers the month boundary, not just startup: a gateway up for two
///     months would otherwise walk off the end of the partitions its own
///     startup created;
///   - logs a LOST audit row at `error!`. It stays best-effort — an audit
///     write must never fail the caller's request — but "best-effort" is not
///     "unobservable".
async fn audit_insert(
    db: &sqlx::PgPool,
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
) {
    // Signed with `NOO_AUDIT_HMAC_KEY` and NOTHING else: without it the row
    // is refused. The derivation from `NOO_JWT_SECRET` (and its public
    // "audit-integrity-fallback" literal) survives only as a VERIFY-ONLY key
    // for rows written before the checkpoint (`audit_integrity`).
    let Some(key) = crate::audit_integrity::current_key() else {
        // Refused, loudly, every time: a row signed with anything but the
        // audit key is a row whoever holds that other key could have forged.
        tracing::error!(
            event_type, actor,
            "audit_write_refused_no_key: NOO_AUDIT_HMAC_KEY is not set, so this security audit \
             row was NOT recorded — run `noo upgrade --stack`, which mints it when absent and \
             recreates the stack"
        );
        crate::audit_spool::note_lost();
        return;
    };
    // The database being away (a Postgres restart during a roll) is not a
    // reason to lose the row: it waits in `audit_spool` and is written as
    // soon as the database answers, stamped with when it happened.
    if write_audit_row_outcome(db, &key, event_type, severity, actor, resource, outcome, details, None).await
        == crate::audit_spool::Outcome::Transient
    {
        let held = crate::audit_spool::enqueue(crate::audit_spool::Pending::Security {
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            details: crate::audit_spool::stamp_queued_at(details),
        });
        if held {
            tracing::warn!(event_type, actor, "audit_write_queued: the database is away; this security audit row is held and will be written when it answers");
        } else {
            tracing::error!(event_type, actor, "audit_write_lost: the database is away and the audit queue is full; this security audit row was NOT recorded");
        }
    }
}

/// Sign one row with hash v2 under `key` and insert it. Returns whether the
/// row landed. Shared by [`audit_insert`] and the boot rows
/// (`audit_integrity::ensure_checkpoint`, which signs its one row with a
/// different key, and `ensure_hash_v2_marker`).
///
/// Every column v2 covers is fixed before signing, and bound explicitly —
/// none is left to a column default. `audit_chain::insert_in_tx` does it, under
/// the chain lock, so the row is linked after the newest one:
///   - `id`: a v4 uuid, as Postgres renders `uuid::text`;
///   - `timestamp`: now (never earlier than the previous row's), truncated to
///     MICROseconds, the precision `timestamptz` stores — the hashed value is
///     the stored value;
///   - `details`: Postgres's own jsonb text for the value (`$1::jsonb::text`),
///     which is what `details::text` reads back; jsonb re-orders keys and
///     re-spaces, so hashing our serde text would not survive the store.
///   - `request_id`: NULL (the gateway has none).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_audit_row(
    db: &sqlx::PgPool,
    key: &[u8],
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
    prev_hash: Option<&str>,
) -> bool {
    // Not queued: these callers act on the answer now (a required view
    // refuses, a boot row is retried at the next boot).
    match write_audit_row_outcome(db, key, event_type, severity, actor, resource, outcome, details, prev_hash).await {
        crate::audit_spool::Outcome::Landed => true,
        crate::audit_spool::Outcome::Transient => {
            tracing::error!(event_type, actor, "audit_write_lost: the database is away; this security audit row was NOT recorded");
            crate::audit_spool::note_lost();
            false
        }
        crate::audit_spool::Outcome::Lost => false,
    }
}

/// [`write_audit_row`], saying WHY a row did not land: `Transient` (the
/// database is away; the caller may hold the row for `audit_spool`) or
/// `Lost` (it would fail again). Only `Lost` logs `audit_write_lost` here; a
/// `Transient` row is the caller's to queue or report.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_audit_row_outcome(
    db: &sqlx::PgPool,
    key: &[u8],
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
    prev_hash: Option<&str>,
) -> crate::audit_spool::Outcome {
    use crate::audit_spool::{is_transient, Outcome};
    let details = match sqlx::query_scalar::<_, String>("SELECT $1::jsonb::text")
        .bind(details)
        .fetch_one(db)
        .await
    {
        Ok(d) => d,
        Err(e) if is_transient(&e) => return Outcome::Transient,
        Err(e) => {
            tracing::error!(
                event_type, actor, error = %e,
                "audit_write_lost: a security audit row was NOT recorded (its details are not jsonb)"
            );
            crate::audit_spool::note_lost();
            return Outcome::Lost;
        }
    };
    // The chain is always linked under the CURRENT audit key, even for the one
    // row (the key hand-over) whose own hash is signed under the retired one.
    let chain_key = crate::audit_integrity::current_key();
    let row = crate::audit_chain::NewRow {
        event_type,
        severity,
        actor,
        resource,
        outcome,
        details: &details,
        prev_hash,
    };
    // The id, the time and both hashes are fixed INSIDE the chain lock
    // (`audit_chain::insert_in_tx`), so a row's time is never earlier than its
    // predecessor's. A missing monthly partition is healed once, as before.
    for attempt in 0..2 {
        match crate::audit_chain::write_row(db, key, chain_key.as_deref(), &row).await {
            Ok(_) => return Outcome::Landed,
            Err(e) if attempt == 0 && is_missing_partition(&e) => {
                crate::audit_partition::ensure_for_heal(db).await;
            }
            Err(e) if is_transient(&e) => return Outcome::Transient,
            Err(e) => {
                tracing::error!(
                    event_type, actor, error = %e,
                    "audit_write_lost: a security audit row was NOT recorded"
                );
                crate::audit_spool::note_lost();
                return Outcome::Lost;
            }
        }
    }
    crate::audit_spool::note_lost();
    Outcome::Lost
}

/// Now, as `timestamptz` will store it: whole microseconds.
pub(crate) fn stored_now() -> chrono::DateTime<chrono::Utc> {
    let us = chrono::Utc::now().timestamp_micros();
    chrono::DateTime::from_timestamp_micros(us).expect("now is in range")
}

/// Insert one fully-formed, already-signed row, healing a missing partition
/// once. Returns whether the row landed. Unchained. Production signs and links
/// through [`write_audit_row`]; this is the test harness's way to plant a row of
/// any shape (v1 hashes, rows from a writer that predates the chain).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_signed_audit_row(
    db: &sqlx::PgPool,
    id: &str,
    ts: chrono::DateTime<chrono::Utc>,
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
    request_id: Option<&str>,
    entry_hash: &str,
    prev_hash: Option<&str>,
) -> bool {
    let row = crate::repo::audit::InsertRow {
        id,
        ts,
        event_type,
        severity,
        actor,
        resource,
        outcome,
        details,
        request_id,
        entry_hash,
        prev_hash,
        chain_seq: None,
        chain_hash: None,
    };
    let run = || crate::repo::audit::insert(db, &row);

    match run().await {
        Ok(_) => true,
        Err(e) if is_missing_partition(&e) => {
            crate::audit_partition::ensure_for_heal(db).await;
            if let Err(e2) = run().await {
                tracing::error!(
                    event_type, actor, error = %e2,
                    "audit_write_lost_after_partition_heal: a security audit row was NOT recorded"
                );
                return false;
            }
            true
        }
        Err(e) => {
            tracing::error!(
                event_type, actor, error = %e,
                "audit_write_lost: a security audit row was NOT recorded"
            );
            false
        }
    }
}

/// Does this error mean "no monthly partition for that timestamp"?
///
/// Matched on the message because Postgres reports it as check_violation
/// (23514), the same SQLSTATE as an ordinary CHECK failure — which is not a
/// thing to heal by creating a partition.
pub(crate) fn is_missing_partition(e: &sqlx::Error) -> bool {
    e.to_string().contains("no partition of relation")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `event_type` string the gateway writes, pinned. Renaming or
    /// adding a kind is a deliberate edit of this list, not drift: existing
    /// rows, alerts and `noo security audit` filters match on these strings.
    /// (Derived from the call sites on origin/dev: 117 distinct strings.)
    const PINNED: &[&str] = &[
        "addon_access_set",
        "agent_archive_decrypt",
        "agent_key_registered",
        "approval_decision",
        "audit_log_read",
        "auth_failure",
        "auth_logout",
        "auth_success",
        "bootstrap_token_create",
        "bootstrap_token_denied",
        "bootstrap_token_revoke",
        "bootstrap_token_used",
        "bundle_apply_reported",
        "channel_ingress_denied",
        "cli_asset_uploaded",
        "config_update",
        "config_update_refused",
        "data_delete",
        "delete_tailscale_device",
        "embedding_migration_cancelled",
        "embedding_migration_cutover",
        "embedding_migration_started",
        "embedding_space_declared",
        "embedding_space_removed",
        "enroll_name_conflict",
        "erasure_archive_purge",
        "exec_approval_decided",
        "exec_approval_requested",
        "exec_denied",
        "grafana_session_issued",
        "graph_entity_cleanup",
        "identity_token_issue",
        "job_cancel",
        "job_cancel_denied",
        "job_submit",
        "kb_hold",
        "kb_purge",
        "kb_retag",
        "kb_roles_grant",
        "kb_roles_revoke",
        "kb_rule_set",
        "kb_team_create",
        "kb_team_delete",
        "kb_unhold",
        "kiosk_tailnet_mint_denied",
        "mcp_external_call",
        "mcp_server_place",
        "mcp_server_register",
        "mcp_server_remove",
        "mcp_server_unplace",
        "mcp_server_update",
        "mcp_tool_call",
        "mesh_rebuild",
        "mesh_restart",
        "mint_join_key",
        "model_alias_declared",
        "model_alias_removed",
        "model_class_declared",
        "model_class_removed",
        "node_bench",
        "node_forgotten",
        "node_gpu_hold",
        "node_gpu_release",
        "operator_cert_registered",
        "operator_cert_revoked",
        "org_create",
        "peer_deregistered",
        "peer_token_minted",
        "prompt_skill_promoted",
        "prompt_skill_rejected",
        "provision_bundle_staged",
        "reservation_release",
        "reservation_take",
        "seat_bundle_applied",
        "seat_bundle_staged",
        "seat_enrolled",
        "seat_token_create",
        "seat_token_denied",
        "seat_token_revoke",
        "security_posture_profile",
        "security_posture_retired_row_removed",
        "security_posture_set",
        "service_key_issue",
        "service_key_retire",
        "service_key_revoke",
        "service_key_revoke_and_disable",
        "service_key_rotate",
        "service_key_self_issue",
        "service_key_self_revoke",
        "service_key_set_quota",
        "setting_flag_set",
        "stack_rebuild",
        "super_admin_set",
        "tailnet_enroll_admitted",
        "tailnet_enroll_denied",
        "task_answered",
        "task_created",
        "task_resubmitted",
        "task_stopped",
        "team_space_link",
        "team_space_unlink",
        "token_allowance_removed",
        "token_allowance_set",
        "tool_exec",
        "user_channel_link",
        "user_channel_unlink",
        "user_create",
        "user_erase",
        "user_erase_refused",
        "user_proposal_approved",
        "user_proposal_denied",
        "user_proposal_failed",
        "user_proposal_filed",
        "user_set_disabled",
        "user_set_org",
        "user_set_password",
        "user_set_role",
        "user_set_scopes",
        "walks_admin_view",
    ];

    #[test]
    fn every_kind_round_trips_through_its_wire_string() {
        for kind in AuditKind::known() {
            assert_eq!(AuditKind::from_wire(kind.as_str()), kind, "{}", kind.as_str());
        }
        assert_eq!(
            AuditKind::from_wire("some_addon_event"),
            AuditKind::Other("some_addon_event".into())
        );
        assert_eq!(AuditKind::Other("x".into()).as_str(), "x");
    }

    #[test]
    fn the_set_of_wire_strings_is_the_pinned_list() {
        let mut got: Vec<String> = AuditKind::known().iter().map(|k| k.as_str().to_string()).collect();
        let n = got.len();
        got.sort();
        got.dedup();
        assert_eq!(got.len(), n, "two kinds share a wire string");
        let mut want: Vec<String> = PINNED.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(got, want, "a kind was renamed, added or dropped: edit PINNED on purpose");
        assert_eq!(PINNED.len(), 119);
    }

    #[test]
    fn auth_failures_are_warning_replay_is_critical_success_is_info() {
        let sev = |kind: AuditKind, outcome: &str| {
            AuditEvent::new(kind, "alice", "gateway").outcome(outcome).resolved_severity()
        };
        assert_eq!(sev(AuditKind::AuthFailure, "user_not_found"), Severity::Warning);
        assert_eq!(sev(AuditKind::AuthFailure, "account_locked"), Severity::Warning);
        assert_eq!(sev(AuditKind::AuthFailure, "bad_password"), Severity::Warning);
        assert_eq!(sev(AuditKind::AuthFailure, "refresh_replay"), Severity::Critical);
        assert_eq!(sev(AuditKind::AuthSuccess, "ok"), Severity::Info);
        assert_eq!(sev(AuditKind::AuthLogout, "ok"), Severity::Info);
    }

    #[test]
    fn an_explicit_severity_beats_the_default_and_the_outcome_words_map() {
        let e = AuditEvent::new(AuditKind::ExecApprovalDecided, "gateway", "tool:x")
            .outcome(Outcome::Denied)
            .severity(Severity::Warning);
        assert_eq!(e.resolved_severity(), Severity::Warning);
        assert_eq!(
            AuditEvent::new(AuditKind::ExecApprovalDecided, "gateway", "tool:x").resolved_severity(),
            Severity::Info
        );
        assert_eq!(Outcome::from("ok"), Outcome::Ok);
        assert_eq!(Outcome::from("denied"), Outcome::Denied);
        assert_eq!(Outcome::from("error"), Outcome::Error);
        assert_eq!(Outcome::from("refused").as_str(), "refused");
        assert_eq!(Outcome::custom("started").as_str(), "started");
        assert_eq!(Severity::from_wire("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_wire("loud"), None);
    }

    #[test]
    fn the_writer_stamps_whole_microseconds() {
        // The hashed time is the stored time: timestamptz keeps microseconds.
        let t = stored_now();
        assert_eq!(t.timestamp_subsec_nanos() % 1_000, 0);
    }
}
