// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The database half of `noo migrate` (i45): what the archive carries beside
//! the dump, and how `noo onboard --from-archive` replays it.
//!
//! A `pg_dump` is per-database, but the roles it names (`noo_app`,
//! `noo_trellion_ddl`, ...) are cluster-global, so the dump carries
//! `ALTER ... OWNER TO` and `GRANT ... TO` for roles it never creates. On a
//! clean server every one of those fails. The 2026-10-12 restore drill showed
//! the result: about 150 "role does not exist" errors, a psql that still
//! exited 0, and "tables restored: 0". The backup script was fixed then
//! (scripts/backup-controller.sh, restore-drill.sh); this is the same fix for
//! the migration archive:
//!
//! - export writes `db/pgroles.sql`: an idempotent CREATE ROLE script for
//!   every `noo_*` role, attributes only, never a password;
//! - export counts the dump's tables per schema IN THE SAME PASS that writes
//!   it, so the manifest's `pg_tables` and the dump are one snapshot;
//! - import runs every step with `ON_ERROR_STOP=1`, shows the first ERROR
//!   line, and accepts the restore only when the live per-schema table counts
//!   equal the manifest's;
//! - a role the stack logs in as that came back without a password is an
//!   error, naming the role and `noo security secrets resync --all`.
//!
//! Passwords never travel in argv (a host `ps` shows argv) and never reach
//! output: psql's statement context is never printed, only its ERROR line.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// The roles file's place in the archive, beside `db/pg.sql.gz`.
pub(crate) const ROLES_MEMBER: &str = "db/pgroles.sql";

/// The roles the stack's services log in as. An archive from before the
/// roles file gets these pre-created NOLOGIN, the way restore-drill does.
pub(crate) const KNOWN_ROLES: &[&str] = &["noo_app", "noo_trellion", "noo_trellion_ddl", "noo_evolve", "noo_evolve_ddl"];

/// The roles EVERY stack logs in as (the gateway, trellion and its DDL
/// broker); onboard mints a store password for each. The evolve pair is
/// used only with the evolve add-on, whose `noo addon enable` mints
/// `NOO_EVOLVE_DDL_PASSWORD`; without it they are never logged in as.
pub(crate) const CORE_LOGIN_ROLES: &[&str] = &["noo_app", "noo_trellion", "noo_trellion_ddl"];

/// The evolve add-on's roles, logged in as only when evolve runs.
pub(crate) const EVOLVE_ROLES: &[&str] = &["noo_evolve", "noo_evolve_ddl"];

/// Does a noomesh.yaml declare `addon` on? `addons:` is the one declaration;
/// evolve is opt-in, so not stated (or no file) is off. A file that does not
/// parse is NOT "not stated": it is an error the caller names.
pub(crate) fn declared_on(noomesh_yaml: Option<&str>, addon: &str) -> Result<bool, String> {
    let Some(text) = noomesh_yaml else { return Ok(false) };
    let v: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    Ok(v.get("addons").and_then(|a| a.get(addon)).and_then(serde_yaml::Value::as_bool).unwrap_or(false))
}

/// Which roles must log in, when the archive's roles file cannot say (an
/// archive from before it): the roles this install logs in as, read from
/// the archive's own noomesh.yaml. The core roles always; the evolve pair
/// when that file declares evolve on.
pub(crate) fn fallback_login_roles(evolve_on: bool) -> BTreeSet<String> {
    let evolve: &[&str] = if evolve_on { EVOLVE_ROLES } else { &[] };
    CORE_LOGIN_ROLES.iter().chain(evolve).map(|r| r.to_string()).collect()
}

/// The same statement scripts/backup-controller.sh uses: one idempotent DO
/// block per live `noo_*` role, LOGIN or NOLOGIN as it is now, never
/// SUPERUSER, CREATEROLE or BYPASSRLS, and no password column read at all.
pub(crate) const ROLES_SQL: &str = r"SELECT format('DO $r$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %L) THEN CREATE ROLE %I %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF; END $r$;', rolname, rolname, CASE WHEN rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN' END) FROM pg_roles WHERE rolname LIKE 'noo\_%' ORDER BY rolname;";

/// Tables per schema in a live database, counted the way pg_dump dumps them:
/// ordinary and partitioned tables, outside the system schemas, and not
/// members of an extension (CREATE EXTENSION recreates those, and pg_dump
/// leaves them out).
pub(crate) const TABLES_SQL: &str = r"SELECT n.nspname || '|' || count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e') GROUP BY n.nspname ORDER BY n.nspname;";

/// Counts a plain pg_dump's tables per schema from its table-of-contents
/// headers (`-- Name: x; Type: TABLE; Schema: mesh; Owner: noo`), skipping
/// COPY data, whose rows are user text and could look like anything.
#[derive(Debug, Default)]
pub(crate) struct DumpTables {
    in_copy: bool,
    pub counts: BTreeMap<String, u64>,
}

impl DumpTables {
    pub(crate) fn line(&mut self, l: &str) {
        let l = l.trim_end_matches(|c: char| c == '\n' || c == '\r');
        if self.in_copy {
            if l == "\\." {
                self.in_copy = false;
            }
            return;
        }
        if l.starts_with("COPY ") && l.ends_with(" FROM stdin;") {
            self.in_copy = true;
            return;
        }
        let Some(rest) = l.strip_prefix("-- Name: ") else { return };
        let mut kind = None;
        let mut schema = None;
        for part in rest.split("; ") {
            if let Some(t) = part.strip_prefix("Type: ") {
                kind = Some(t);
            } else if let Some(s) = part.strip_prefix("Schema: ") {
                schema = Some(s);
            }
        }
        if let (Some("TABLE"), Some(s)) = (kind, schema) {
            if s != "-" {
                *self.counts.entry(s.to_string()).or_default() += 1;
            }
        }
    }
}

/// Dump `noomesh` from the `pg` container into `out` (gzip, 0600, created
/// fresh) and count its tables per schema in the same pass, so the count is
/// the dump's own and cannot race a migration that runs mid-export.
pub(crate) fn dump_counting(pg: &str, out: &Path) -> Result<BTreeMap<String, u64>, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    let mut child = Command::new("docker")
        .args(["exec", pg, "pg_dump", "-U", "noo", "noomesh"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("pg_dump: {e}"))?;
    let stdout = child.stdout.take().ok_or("pg_dump: no stdout")?;
    let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tables = DumpTables::default();
    let mut reader = BufReader::new(stdout);
    let mut buf: Vec<u8> = Vec::new();
    let streamed = (|| -> Result<(), String> {
        loop {
            buf.clear();
            if reader.read_until(b'\n', &mut buf).map_err(|e| format!("pg_dump read: {e}"))? == 0 {
                return Ok(());
            }
            gz.write_all(&buf).map_err(|e| format!("gzip: {e}"))?;
            tables.line(&String::from_utf8_lossy(&buf));
        }
    })();
    if streamed.is_err() {
        // Stopped reading: pg_dump would block on a full pipe forever.
        let _ = child.kill();
    }
    let status = child.wait().map_err(|e| format!("pg_dump: {e}"))?;
    streamed?;
    gz.finish().map_err(|e| format!("gzip: {e}"))?;
    if !status.success() {
        return Err(format!("pg_dump failed ({status})"));
    }
    if tables.counts.values().sum::<u64>() == 0 {
        return Err("the dump holds no tables; refusing to call it a migration".into());
    }
    Ok(tables.counts)
}

/// Run `sql` through psql in the `pg` container, database `db`, on stdin.
/// Returns stdout. `ON_ERROR_STOP=1`: the first failing statement ends the
/// run and its ERROR line is the error (never the statement context).
pub(crate) fn psql(pg: &str, db: &str, sql: &mut dyn Read, tuples: bool) -> Result<String, String> {
    let mut child = Command::new("docker")
        .args(psql_args(pg, db, tuples))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("psql: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("psql: no stdout")?;
    let mut stderr = child.stderr.take().ok_or("psql: no stderr")?;
    // Both pipes drain on their own threads: a restore can print far more
    // than a pipe holds, and a full pipe would stall psql mid-stream.
    let out_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let mut stdin = child.stdin.take().ok_or("psql: no stdin")?;
    // A write error is psql having stopped early (ON_ERROR_STOP): its own
    // ERROR line, read below, is the reason worth showing.
    let _ = std::io::copy(sql, &mut stdin);
    drop(stdin);
    let status = child.wait().map_err(|e| format!("psql: {e}"))?;
    let out = out_t.join().unwrap_or_default();
    let err = err_t.join().unwrap_or_default();
    if status.success() {
        Ok(out)
    } else {
        Err(first_error(&err))
    }
}

/// `docker exec -i <pg> psql ...`: the statements arrive on stdin, never as
/// `-c` (argv is visible to every local user), and the first error stops it.
pub(crate) fn psql_args<'a>(pg: &'a str, db: &'a str, tuples: bool) -> Vec<&'a str> {
    let mut args = vec!["exec", "-i", pg, "psql", "-q", "-X", "-v", "ON_ERROR_STOP=1", "-U", "noo", "-d", db];
    if tuples {
        args.push("-tA");
    }
    args
}

/// The first `ERROR:` line psql printed, and nothing else: its LINE and
/// STATEMENT context can quote the statement, and on the role step the
/// statement holds a password.
pub(crate) fn first_error(stderr: &str) -> String {
    stderr
        .lines()
        .find_map(|l| l.find("ERROR:").map(|i| l[i..].trim().to_string()))
        .unwrap_or_else(|| "psql failed without an ERROR line".into())
}

/// Live tables per schema (see [`TABLES_SQL`]).
pub(crate) fn live_tables(pg: &str) -> Result<BTreeMap<String, u64>, String> {
    let out = psql(pg, "noomesh", &mut TABLES_SQL.as_bytes(), true)?;
    Ok(parse_tables(&out))
}

pub(crate) fn parse_tables(out: &str) -> BTreeMap<String, u64> {
    out.lines()
        .filter_map(|l| l.trim().rsplit_once('|'))
        .filter_map(|(s, n)| n.parse::<u64>().ok().map(|n| (s.to_string(), n)))
        .collect()
}

/// The restore is accepted only when every schema has exactly the tables
/// the dump carried. An archive from before the count (no `pg_tables`) can
/// only be held to "some tables came back".
pub(crate) fn table_check(expected: Option<&BTreeMap<String, u64>>, got: &BTreeMap<String, u64>) -> Result<String, String> {
    let total: u64 = got.values().sum();
    let Some(want) = expected else {
        return if total > 0 {
            Ok(format!("{total} tables restored (this archive predates the table count, so only non-zero is checked)"))
        } else {
            Err("the restore produced no tables".into())
        };
    };
    let schemas: BTreeSet<&String> = want.keys().chain(got.keys()).collect();
    let off: Vec<String> = schemas
        .into_iter()
        .filter_map(|s| {
            let (w, g) = (want.get(s).copied().unwrap_or(0), got.get(s).copied().unwrap_or(0));
            (w != g).then(|| format!("{s}: {w} in the archive, {g} restored"))
        })
        .collect();
    if off.is_empty() {
        Ok(format!("{total} tables restored, schema for schema as exported"))
    } else {
        Err(format!("the restored tables do not match the archive ({})", off.join("; ")))
    }
}

/// The table counts an archive's manifest carries, when it carries them.
pub(crate) fn manifest_tables(manifest: &serde_json::Value) -> Option<BTreeMap<String, u64>> {
    let m = manifest.get("pg_tables")?.as_object()?;
    Some(m.iter().filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n))).collect())
}

/// The roles in a roles file that log in (`CREATE ROLE <name> LOGIN`).
pub(crate) fn login_roles(script: &str) -> BTreeSet<String> {
    script
        .lines()
        .filter_map(|l| {
            let rest = &l[l.find("CREATE ROLE ")? + "CREATE ROLE ".len()..];
            let mut words = rest.split_whitespace();
            let name = words.next()?.trim_matches('"');
            (words.next()? == "LOGIN").then(|| name.to_string())
        })
        .collect()
}

/// The fallback for an archive with no roles file: the known roles, NOLOGIN.
pub(crate) fn fallback_roles_script() -> String {
    KNOWN_ROLES
        .iter()
        .map(|r| format!("DO $r$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{r}') THEN CREATE ROLE {r} NOLOGIN; END IF; END $r$;\n"))
        .collect()
}

/// The `noo_*` roles that exist now.
pub(crate) fn noo_roles(pg: &str) -> Result<BTreeSet<String>, String> {
    let out = psql(pg, "postgres", &mut r"SELECT rolname FROM pg_roles WHERE rolname LIKE 'noo\_%';".as_bytes(), true)?;
    Ok(out.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// The roles that came back without a password but must log in: created by
/// the roles file rather than from the secret store (which sets one), and
/// LOGIN in that file.
pub(crate) fn roles_without_password(
    created_without_password: &BTreeSet<String>,
    login: &BTreeSet<String>,
) -> Vec<String> {
    created_without_password.iter().filter(|r| login.contains(*r)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dump_count_reads_table_headers_and_skips_copy_data() {
        let dump = "\
-- Name: mesh; Type: SCHEMA; Schema: -; Owner: noo
CREATE SCHEMA mesh;
-- Name: cluster_nodes; Type: TABLE; Schema: mesh; Owner: noo
CREATE TABLE mesh.cluster_nodes (id text);
-- Name: pages; Type: TABLE; Schema: trellion; Owner: noo_trellion_ddl
CREATE TABLE trellion.pages (id text);
-- Name: v; Type: VIEW; Schema: mesh; Owner: noo
-- Data for Name: cluster_nodes; Type: TABLE DATA; Schema: mesh; Owner: noo
COPY mesh.cluster_nodes (id) FROM stdin;
-- Name: fake; Type: TABLE; Schema: mesh; Owner: noo
\\.
-- Name: notes; Type: TABLE; Schema: mesh; Owner: noo
";
        let mut t = DumpTables::default();
        for l in dump.lines() {
            t.line(l);
        }
        assert_eq!(t.counts.get("mesh"), Some(&2), "{:?}", t.counts);
        assert_eq!(t.counts.get("trellion"), Some(&1));
        assert_eq!(t.counts.len(), 2, "views, schemas and TABLE DATA are not tables: {:?}", t.counts);
    }

    #[test]
    fn the_restore_must_match_the_archive_schema_for_schema() {
        let want: BTreeMap<String, u64> = [("mesh".to_string(), 120), ("trellion".to_string(), 30)].into();
        let same = want.clone();
        assert!(table_check(Some(&want), &same).is_ok());
        let short: BTreeMap<String, u64> = [("mesh".to_string(), 119), ("trellion".to_string(), 30)].into();
        let e = table_check(Some(&want), &short).unwrap_err();
        assert!(e.contains("mesh: 120 in the archive, 119 restored"), "{e}");
        let missing: BTreeMap<String, u64> = [("mesh".to_string(), 120)].into();
        assert!(table_check(Some(&want), &missing).unwrap_err().contains("trellion: 30 in the archive, 0 restored"));
        let extra: BTreeMap<String, u64> = [("mesh".to_string(), 120), ("trellion".to_string(), 30), ("evolve".to_string(), 4)].into();
        assert!(table_check(Some(&want), &extra).is_err(), "tables the archive never had are a mismatch too");
        // An archive from before the count is held to non-zero.
        assert!(table_check(None, &same).is_ok());
        assert!(table_check(None, &BTreeMap::new()).is_err());
    }

    #[test]
    fn the_manifest_count_round_trips() {
        let m = serde_json::json!({"pg_tables": {"mesh": 120, "public": 3}});
        let t = manifest_tables(&m).expect("pg_tables read");
        assert_eq!(t.get("mesh"), Some(&120));
        assert!(manifest_tables(&serde_json::json!({})).is_none());
        assert_eq!(parse_tables("mesh|120\npublic|3\n"), t);
    }

    #[test]
    fn the_roles_sql_carries_no_password_and_no_power() {
        let up = ROLES_SQL.to_ascii_uppercase();
        assert!(!up.contains("PASSWORD") && !up.contains("ROLPASSWORD"), "the roles file must never carry a password");
        for weak in ["NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOBYPASSRLS", "IF NOT EXISTS"] {
            assert!(up.contains(weak), "missing {weak}");
        }
        assert!(ROLES_SQL.contains(r"LIKE 'noo\_%'"), "only the noo_* roles, with _ escaped");
        let fb = fallback_roles_script();
        assert_eq!(fb.lines().count(), KNOWN_ROLES.len());
        assert!(fb.lines().all(|l| l.contains("NOLOGIN") && !l.to_ascii_uppercase().contains("PASSWORD")));
    }

    #[test]
    fn login_roles_reads_the_roles_file() {
        let script = "\
DO $r$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_app') THEN CREATE ROLE noo_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF; END $r$;
DO $r$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_readonly') THEN CREATE ROLE noo_readonly NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF; END $r$;
";
        let l = login_roles(script);
        assert!(l.contains("noo_app"));
        assert!(!l.contains("noo_readonly"), "NOLOGIN is not LOGIN: {l:?}");
    }

    #[test]
    fn a_login_role_back_without_a_password_is_named() {
        let created: BTreeSet<String> = ["noo_app", "noo_readonly", "noo_extra"].iter().map(|s| s.to_string()).collect();
        let login: BTreeSet<String> = ["noo_app", "noo_extra"].iter().map(|s| s.to_string()).collect();
        let bad = roles_without_password(&created, &login);
        assert_eq!(bad, vec!["noo_app".to_string(), "noo_extra".to_string()], "LOGIN roles the file created; noo_readonly is NOLOGIN");
        assert!(roles_without_password(&BTreeSet::new(), &login).is_empty());
    }

    /// An archive without a roles file: the five fallback roles came back
    /// NOLOGIN with no password. The core three are what every stack logs in
    /// as, so they are the error; the evolve pair is only used with the
    /// add-on (whose enable step mints their passwords), so it is not.
    #[test]
    fn an_old_archive_holds_the_core_roles_to_a_password() {
        let created: BTreeSet<String> = KNOWN_ROLES.iter().map(|s| s.to_string()).collect();
        let bad = roles_without_password(&created, &fallback_login_roles(false));
        assert_eq!(bad, vec!["noo_app".to_string(), "noo_trellion".into(), "noo_trellion_ddl".into()]);
        assert!(CORE_LOGIN_ROLES.iter().chain(EVOLVE_ROLES).all(|r| KNOWN_ROLES.contains(r)));
    }

    /// The archive's noomesh.yaml declares evolve on, and the store gave its
    /// roles no password: the stack would log in as them, so it is an error.
    #[test]
    fn an_old_archive_with_evolve_declared_on_holds_its_roles_too() {
        let yaml = "addons:\n  trellion: true\n  evolve: true\n";
        assert_eq!(declared_on(Some(yaml), "evolve"), Ok(true));
        let created: BTreeSet<String> = ["noo_evolve", "noo_evolve_ddl"].iter().map(|s| s.to_string()).collect();
        let bad = roles_without_password(&created, &fallback_login_roles(true));
        assert_eq!(bad, vec!["noo_evolve".to_string(), "noo_evolve_ddl".into()]);
        // Off, not stated, or no file: evolve's roles stay a warning.
        for off in [Some("addons:\n  evolve: false\n"), Some("addons:\n  trellion: true\n"), None] {
            assert_eq!(declared_on(off, "evolve"), Ok(false), "{off:?}");
        }
        assert!(roles_without_password(&created, &fallback_login_roles(false)).is_empty());
        // A file that does not parse is its own answer, never "not stated".
        assert!(declared_on(Some("addons: [unclosed"), "evolve").is_err());
    }

    #[test]
    fn every_statement_reaches_psql_on_stdin_and_stops_at_the_first_error() {
        for tuples in [false, true] {
            let a = psql_args("noo-postgres", "noomesh", tuples);
            assert!(a.windows(2).any(|w| w == ["-v", "ON_ERROR_STOP=1"]), "{a:?}");
            assert!(a.contains(&"-i"), "statements arrive on stdin: {a:?}");
            assert!(!a.contains(&"-c"), "never a statement in argv: {a:?}");
        }
    }

    #[test]
    fn only_the_error_line_is_ever_shown() {
        let stderr = "psql:<stdin>:1: ERROR:  syntax error at or near \"x\"\nLINE 1: CREATE ROLE noo_app LOGIN PASSWORD 'hunter2'\n";
        let e = first_error(stderr);
        assert!(e.starts_with("ERROR:"), "{e}");
        assert!(!e.contains("hunter2") && !e.contains("LINE"), "{e}");
        assert_eq!(first_error("LINE 1: PASSWORD 'x'\n"), "psql failed without an ERROR line");
    }
}
