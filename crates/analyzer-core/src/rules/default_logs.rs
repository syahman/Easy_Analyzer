//! Default triage rules. Findings describe evidence to review, not a verdict.
use super::{decoded, finding};
use crate::execution::{ExecutionContext, Stage};
use crate::model::*;
use regex::Regex;
use std::{collections::BTreeMap, sync::OnceLock};

enum Detector {
    Event(&'static str, &'static [&'static str]),
    PrivilegedGroup,
    RemoteDesktop,
    AdminShare,
    KerberosRc4,
    WindowsCommand(Regex),
    WebRequest(Regex),
    WebAgent(Regex),
    WebMethod,
    WebStatus(u16, u16),
    WebDenied,
    WebError(Regex),
    LinuxText(Regex),
    LoginFailure,
    RootLogin,
    PasswordLogin,
}
struct Rule {
    id: &'static str,
    severity: Severity,
    title: &'static str,
    detail: &'static str,
    advice: &'static str,
    detector: Detector,
}
const SECURITY: &str = "Microsoft-Windows-Security-Auditing";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";

fn field<'a>(log: &'a LogData, name: &str) -> Option<&'a str> {
    log.fields.get(name).map(String::as_str).or_else(|| {
        let suffix = format!(".{name}");
        let text_suffix = format!(".{name}.#text");
        log.fields.iter().find_map(|(key, value)| {
            (key.ends_with(&suffix) || key.ends_with(&text_suffix)).then_some(value.as_str())
        })
    })
}
fn provider(log: &LogData) -> Option<&str> {
    log.fields.iter().find_map(|(key, value)| {
        key.ends_with("Provider.#attributes.Name")
            .then_some(value.as_str())
    })
}
struct Context<'a> {
    log: &'a LogData,
    raw: &'a str,
    provider: Option<&'a str>,
    event_id: Option<&'a str>,
    uri: Option<String>,
}
impl Context<'_> {
    fn event(&self, expected_provider: &str, ids: &[&str]) -> bool {
        self.log.category == "windows_event"
            && self
                .provider
                .is_some_and(|p| p.eq_ignore_ascii_case(expected_provider))
            && self.event_id.is_some_and(|id| ids.contains(&id))
    }
    fn security(&self, ids: &[&str]) -> bool {
        self.event(SECURITY, ids)
    }
}
pub(super) fn authentication_event(log: &LogData, id: &str) -> bool {
    log.category == "windows_event"
        && provider(log).is_none_or(|p| p.eq_ignore_ascii_case(SECURITY))
        && field(log, "event_id") == Some(id)
}
impl Detector {
    fn matches(&self, context: &Context<'_>) -> bool {
        let log = context.log;
        let raw = context.raw;
        match self {
            Self::Event(p, ids) => context.event(p, ids),
            Self::PrivilegedGroup => {
                context.security(&["4728", "4732", "4756"])
                    && field(log, "TargetSid").is_some_and(|sid| {
                        sid == "S-1-5-32-544"
                            || (sid.starts_with("S-1-5-21-")
                                && ["-512", "-518", "-519"].iter().any(|s| sid.ends_with(s)))
                    })
            }
            Self::RemoteDesktop => {
                context.security(&["4624"]) && field(log, "LogonType") == Some("10")
            }
            Self::AdminShare => {
                context.security(&["5140", "5145"])
                    && field(log, "ShareName").is_some_and(|s| {
                        let s = s.to_ascii_lowercase();
                        s.ends_with("\\admin$") || s.ends_with("\\c$")
                    })
            }
            Self::KerberosRc4 => {
                context.security(&["4769"])
                    && field(log, "TicketEncryptionType")
                        .is_some_and(|s| s.eq_ignore_ascii_case("0x17") || s == "23")
                    && field(log, "Status").is_none_or(|s| s == "0x0" || s == "0")
            }
            Self::WindowsCommand(pattern) => {
                (context.security(&["4688"])
                    && field(log, "CommandLine").is_some_and(|s| pattern.is_match(s)))
                    || (context.event("Microsoft-Windows-PowerShell", &["4104"])
                        && field(log, "ScriptBlockText").is_some_and(|s| pattern.is_match(s)))
            }
            Self::WebRequest(pattern) => {
                matches!(log.category.as_str(), "web_access" | "web_error")
                    && context.uri.as_deref().is_some_and(|s| pattern.is_match(s))
            }
            Self::WebAgent(pattern) => {
                log.category == "web_access"
                    && field(log, "user_agent").is_some_and(|s| pattern.is_match(s))
            }
            Self::WebMethod => {
                log.category == "web_access"
                    && field(log, "method").is_some_and(|s| {
                        ["TRACE", "CONNECT", "PROPFIND"].contains(&s.to_ascii_uppercase().as_str())
                    })
            }
            Self::WebStatus(min, max) => {
                log.category == "web_access"
                    && field(log, "status")
                        .and_then(|s| s.parse::<u16>().ok())
                        .is_some_and(|s| (*min..=*max).contains(&s))
            }
            Self::WebDenied => {
                log.category == "web_access" && matches!(field(log, "status"), Some("401" | "403"))
            }
            Self::WebError(pattern) => {
                log.category == "web_error"
                    && field(log, "message").is_some_and(|s| pattern.is_match(s))
            }
            // Do not search EVTX JSON, web URLs, or binary hex as Linux commands.
            Self::LinuxText(pattern) => log.category == "auth_text" && pattern.is_match(raw),
            Self::LoginFailure => {
                field(log, "action") == Some("login_failure") || authentication_event(log, "4625")
            }
            Self::RootLogin => {
                field(log, "action") == Some("login_success")
                    && field(log, "user") == Some("root")
                    && field(log, "client_ip").is_some_and(|s| !s.is_empty() && s != "-")
            }
            Self::PasswordLogin => {
                log.category == "auth_text"
                    && field(log, "action") == Some("login_success")
                    && raw.to_ascii_lowercase().contains("accepted password for ")
            }
        }
    }
}
fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        use Detector::*;
        use Severity::*;
        let re = |s: &str| Regex::new(s).expect("built-in rule regex");
        let command = r"(?i)(?:-(?:enc|encodedcommand)\b|frombase64string|(?:curl|wget)\b[^\r\n]*\|\s*(?:sh|bash)|/dev/tcp/|(?:invoke-expression|iex)\s*\(|downloadstring\s*\(|\bmimikatz\b|\bsekurlsa::|\bprocdump\b[^\r\n]*\blsass\b)";
        let mut r = vec![];
        let mut add = |id, severity, title, detail, advice, detector| r.push(Rule { id, severity, title, detail, advice, detector });
        add(
            "event-log-clear",
            High,
            "Event log cleared",
            "Windows audit or event logs were cleared.",
            "Verify the account that cleared the logs and maintenance records; correlate earlier logons, processes, and remote access.",
            Event(EVENTLOG, &["1102"]),
        );
        add(
            "system-log-clear",
            High,
            "System event log cleared",
            "The Eventlog provider reported log clearing event 104.",
            "Verify the cleared log channels, the acting account, and authorization records.",
            Event(EVENTLOG, &["104"]),
        );
        add(
            "audit-policy-change",
            High,
            "Audit policy or audit privilege changed",
            "Audit policy or object auditing configuration changed (4719/4907/4912).",
            "Compare audit configurations before and after the change; check whether critical auditing was disabled.",
            Event(SECURITY, &["4719", "4907", "4912"]),
        );
        add(
            "audit-service-stop",
            Medium,
            "Event log service stopped",
            "The Eventlog provider reported the event log service stopping (1100).",
            "Check the cause against system shutdown, maintenance records, and service status.",
            Event(EVENTLOG, &["1100"]),
        );
        add(
            "privileged-group-member",
            High,
            "Privileged group gained a member",
            "A member was added to the Administrators group or to a domain group with privileged SIDs.",
            "Confirm the new member's identity and approval; review subsequent privileged operations.",
            PrivilegedGroup,
        );
        add(
            "account-hash-access",
            High,
            "Account password hash accessed",
            "Audit event 4782 means an account password hash was accessed; migration tools can also trigger it.",
            "Verify the accessing principal, account migration tasks, and related processes.",
            Event(SECURITY, &["4782"]),
        );
        add(
            "sid-history-added",
            High,
            "SID History added to account",
            "Audit event 4765 means SID History was added to an account.",
            "Verify domain migration authorization and the added SID privileges.",
            Event(SECURITY, &["4765"]),
        );
        add(
            "security-package-change",
            High,
            "Security authentication package or trusted logon process loaded",
            "Authentication package, trusted logon process, or security package registration (4610/4611/4622).",
            "Verify component paths, signatures, system startup, and security software installation records.",
            Event(SECURITY, &["4610", "4611", "4622"]),
        );
        add(
            "windows-risk-command",
            High,
            "Windows logs contain high-risk execution patterns",
            "Process creation or PowerShell script logs show encoded execution, download-and-execute, or credential access patterns.",
            "Verify the full command, script source, parent process, and executing account.",
            WindowsCommand(re(command)),
        );
        add(
            "account-created",
            Medium,
            "New Windows account created",
            "Audit event 4720 indicates account creation.",
            "Verify the creator, account purpose, permissions, and later logons.",
            Event(SECURITY, &["4720"]),
        );
        add(
            "account-enabled",
            Medium,
            "Windows account enabled",
            "Audit event 4722 indicates an account was enabled.",
            "Verify why a disabled account was re-enabled and who authorized it.",
            Event(SECURITY, &["4722"]),
        );
        add(
            "account-changed",
            Medium,
            "Windows account attributes or name changed",
            "Account attribute modification or rename (4738/4781).",
            "Verify the changed fields, the acting principal, and authorization records.",
            Event(SECURITY, &["4738", "4781"]),
        );
        add(
            "password-reset",
            Medium,
            "Windows password reset attempt",
            "Audit event 4724 indicates an account password reset was attempted; check the event result.",
            "Verify the result, target account, and who initiated the reset.",
            Event(SECURITY, &["4724"]),
        );
        add(
            "security-group-member",
            Medium,
            "Security group gained a member",
            "Security group membership added (4728/4732/4756).",
            "Verify the target group's privileges and who authorized the membership change.",
            Event(SECURITY, &["4728", "4732", "4756"]),
        );
        add(
            "account-locked",
            Medium,
            "Windows account locked out",
            "Audit event 4740 indicates an account was locked out.",
            "Correlate failed logons, the calling host, and legitimate users mistyping passwords.",
            Event(SECURITY, &["4740"]),
        );
        add(
            "service-installed",
            Medium,
            "Windows service installed",
            "Audit event 4697 indicates a service install, possibly for persistence.",
            "Verify the service executable path, account, signature, and install authorization.",
            Event(SECURITY, &["4697"]),
        );
        add(
            "system-service-installed",
            Medium,
            "System log recorded a new service",
            "Service Control Manager event 7045 indicates a service install.",
            "Verify the service path, start type, service account, and install source.",
            Event("Service Control Manager", &["7045"]),
        );
        add(
            "scheduled-task-change",
            Medium,
            "Windows scheduled task created, enabled, or modified",
            "Scheduled task creation, enablement, or update (4698/4700/4702).",
            "Verify the task action, triggers, executing principal, and persistence risk.",
            Event(SECURITY, &["4698", "4700", "4702"]),
        );
        add(
            "user-right-change",
            Medium,
            "Windows user right assignment changed",
            "User right assigned or revoked (4704/4705).",
            "Verify the modified right, the account, and the approval.",
            Event(SECURITY, &["4704", "4705"]),
        );
        add(
            "explicit-credentials",
            Medium,
            "Explicit credential logon attempt",
            "Audit event 4648 indicates an explicit credential logon attempt; legitimate administration can also trigger it.",
            "Verify the initiating process, target server, account, and remote administration records.",
            Event(SECURITY, &["4648"]),
        );
        add(
            "admin-share-access",
            Medium,
            "Windows administrative share accessed",
            "Access to or an access check on the ADMIN$ or C$ share was detected.",
            "Verify whether the access was approved, the source host, target files, and remote operations authorization.",
            AdminShare,
        );
        add(
            "kerberos-rc4-ticket",
            Medium,
            "Kerberos service ticket uses RC4",
            "The service ticket uses RC4; this is an encryption configuration lead and cannot by itself prove ticket attacks.",
            "Verify the service account encryption configuration and request frequency, and assess AES compatibility step by step.",
            KerberosRc4,
        );
        add(
            "firewall-policy-change",
            Medium,
            "Windows firewall policy changed",
            "Firewall rule or policy added, removed, or changed (4946/4947/4948/4950/4956).",
            "Verify whether the changed rules opened sensitive ports and check authorization records.",
            Event(SECURITY, &["4946", "4947", "4948", "4950", "4956"]),
        );
        add(
            "account-state-change",
            Low,
            "Windows account disabled, deleted, or unlocked",
            "Account lifecycle change (4725/4726/4767).",
            "Verify account management records and whether the change was expected.",
            Event(SECURITY, &["4725", "4726", "4767"]),
        );
        add(
            "special-privileges",
            Low,
            "Logon session assigned special privileges",
            "Audit event 4672 means a new logon received special privileges; common for system accounts.",
            "Watch for unexpected accounts and correlate logon type, source address, and operations.",
            Event(SECURITY, &["4672"]),
        );
        add(
            "rdp-login",
            Low,
            "Remote desktop logon",
            "Successful logon event 4624 with LogonType 10.",
            "Verify the source, account, and remote desktop usage authorization.",
            RemoteDesktop,
        );
        add(
            "kerberos-preauth-failure",
            Low,
            "Kerberos pre-authentication failed",
            "Audit event 4771 indicates Kerberos pre-authentication failure.",
            "Review failure codes and sources; use frequency to distinguish password typos from attack leads.",
            Event(SECURITY, &["4771"]),
        );
        add(
            "web-sql-injection",
            High,
            "Web SQL injection patterns",
            "The URI shows UNION SELECT, boolean injection, or time-delay function patterns.",
            "Correlate request parameters, application/database logs, and response content to check for exploitation.",
            WebRequest(re(r#"(?i)(?:\bunion\s+(?:all\s+)?select\b|\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b|['"]\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\binformation_schema\b)"#)),
        );
        add(
            "web-command-injection",
            High,
            "Web command execution patterns",
            "The URI shows command chaining, download-and-execute, or reverse connection patterns.",
            "Verify response and host process evidence; a request alone cannot confirm execution.",
            WebRequest(re(r"(?i)(?:[;|`]\s*(?:curl|wget|bash|sh|cmd|powershell|cat|id|whoami)\b|\$\(\s*(?:id|whoami|curl|wget|cat)\b|/dev/tcp/|\b(?:cmd\.exe|powershell\.exe)\b)")),
        );
        add(
            "web-jndi",
            High,
            "Web JNDI lookup patterns",
            "The URI shows JNDI LDAP/RMI/DNS lookup expressions.",
            "Correlate Java application logs, DNS/outbound connections, and component versions.",
            WebRequest(re(r"(?i)\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http)\s*:")),
        );
        add(
            "web-include",
            High,
            "Web file inclusion or code execution patterns",
            "The URI shows PHP filter/input stream, data stream, or expect execution wrappers.",
            "Verify parameter usage, application errors, responses, and files written to disk.",
            WebRequest(re(r"(?i)(?:php://(?:filter|input)|expect://|data://text/plain|\bauto_prepend_file\b|\ballow_url_include\b)")),
        );
        add(
            "web-probe",
            Medium,
            "Web path traversal or sensitive file probing",
            "The URI shows directory traversal, system-sensitive files, environment configuration, or Git metadata paths.",
            "Verify response codes, actual response content, and application file access records.",
            WebRequest(re(r"(?i)(?:\.\.[/\\]|/etc/(?:passwd|shadow)|/proc/self|/(?:\.env(?:[/?#]|$)|\.git(?:[/#?]|$)|\.svn/)|\bwin\.ini\b|\bboot\.ini\b)")),
        );
        add(
            "web-xss",
            Medium,
            "Web cross-site scripting patterns",
            "The URI shows script tags, JavaScript protocol, or event handler patterns.",
            "Verify whether parameters are reflected or stored, plus output encoding and actual page behavior.",
            WebRequest(re(r"(?i)(?:<\s*script\b|javascript\s*:|\bon(?:error|load|mouseover)\s*=|<\s*(?:svg|img)\b[^>]*\bon\w+\s*=)")),
        );
        add(
            "web-ssrf",
            Medium,
            "Web internal network or cloud metadata URL parameter",
            "Query parameters contain loopback addresses, common private network addresses, or cloud metadata addresses.",
            "Verify whether the parameter makes the server fetch the URL, and check actual outbound access records.",
            WebRequest(re(r"(?i)[?&][^=&]+=(?:https?://)(?:localhost\b|127\.|\[::1\]|169\.254\.169\.254\b|10\.\d+\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")),
        );
        add(
            "web-shell-path",
            Medium,
            "Web common webshell path",
            "The request hit a common webshell filename or a script path in an upload directory.",
            "Verify whether the file actually exists, plus its content, modified time, and deployment records.",
            WebRequest(re(r"(?i)(?:/(?:webshell|shell|cmd|c99|r57|b374k)\.(?:php|aspx?|jsp)(?:[/?#]|$)|/(?:uploads?|files)/[^?#]*\.(?:php|aspx?|jsp)(?:[/?#]|$))")),
        );
        add(
            "web-sql-error",
            Medium,
            "Web error log contains database errors",
            "The error message shows SQL syntax, Oracle error codes, or database driver errors.",
            "Correlate requests in the same window with the application stack; check malformed input and database state.",
            WebError(re(r"(?i)(?:SQL syntax|SQLSTATE\[|ORA-\d{5}|mysqli?_(?:query|fetch)|postgres[^\r\n]*ERROR)")),
        );
        add(
            "web-admin-probe",
            Low,
            "Web admin, debug, or backup endpoint access",
            "The URI accessed common admin, debug, configuration, or backup endpoints.",
            "Verify the endpoint's exposure, authentication, responses, and normal operations sources.",
            WebRequest(re(r"(?i)(?:/(?:wp-login\.php|wp-admin|phpmyadmin|actuator|server-status|swagger)(?:[/?#]|$)|\.(?:bak|old|sql|backup)(?:[?#]|$))")),
        );
        add(
            "web-scanner-agent",
            Low,
            "Web scanner tool User-Agent",
            "The request User-Agent matches a common scanner tool signature; signatures can be forged.",
            "Verify authorized scanning plans, source addresses, and request frequency.",
            WebAgent(re(r"(?i)(?:sqlmap|nikto|nuclei|masscan|zgrab|gobuster|dirbuster|acunetix|nessus)")),
        );
        add(
            "web-unusual-method",
            Low,
            "Web uncommon request method",
            "TRACE, CONNECT, or PROPFIND requests were detected.",
            "Verify whether the service requires the method and check returned results.",
            WebMethod,
        );
        add(
            "web-access-denied",
            Low,
            "Web authentication failure or access denied",
            "Web returned 401 or 403; this may be routine access control.",
            "Check for unauthorized access probing using frequency, account, and target path.",
            WebDenied,
        );
        add(
            "web-server-error",
            Low,
            "Web server error response",
            "Web returned 500-599, possibly application faults or abnormal input.",
            "Correlate error logs, request parameters, and service health.",
            WebStatus(500, 599),
        );
        add(
            "linux-risk-command",
            High,
            "Linux logs contain high-risk commands",
            "Text logs show download-and-execute, reverse connection, or encoded execution patterns.",
            "Verify whether the commands actually ran, the actor, and related processes.",
            LinuxText(re(command)),
        );
        add(
            "linux-evidence-clear",
            High,
            "Linux log or audit disabled patterns",
            "Text logs show commands for clearing logs, wiping history, or disabling audit.",
            "Verify maintenance authorization, log integrity, audit status, and operation time.",
            LinuxText(re(r"(?i)(?:\bauditctl\s+-e\s+0\b|\bhistory\s+-c\b|\b(?:rm|truncate)\b[^\r\n]*(?:/var/log/|\.bash_history)|(?:>|tee\s+)\s*/var/log/(?:auth\.log|secure|wtmp|btmp|audit/))")),
        );
        add(
            "linux-account-change",
            Medium,
            "Linux account or group management",
            "Account management programs recorded new accounts, groups, or user attribute changes.",
            "Verify account management authorization, privileges, and related logon records.",
            LinuxText(re(r"(?i)(?:\b(?:useradd|usermod|userdel|groupadd|groupmod|groupdel)\b[^\r\n]*(?:new user|new group|change|delete|COMMAND=)|\bCOMMAND=[^\r\n]*\b(?:useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd)\b)")),
        );
        add(
            "linux-sudo-command",
            Medium,
            "Linux sudo executed command",
            "sudo logs recorded a privileged command execution.",
            "Verify the originating account, target user, full command, and authorized operations tasks.",
            LinuxText(re(r"(?i)\bsudo(?:\[\d+\])?\s*:[^\r\n]*\bCOMMAND=")),
        );
        add(
            "linux-sudo-denied",
            Medium,
            "Linux privilege authentication failure or denial",
            "sudo/su logs recorded wrong passwords, authentication failures, or missing sudo rights.",
            "Correlate user, terminal, and retry frequency; check for unexpected privilege escalation.",
            LinuxText(re(r"(?i)(?:\bsudo(?:\[\d+\])?\s*:[^\r\n]*(?:incorrect password|not in the sudoers|authentication failure|NOT in sudoers)|pam_unix\((?:sudo|su):auth\)[^\r\n]*authentication failure)")),
        );
        add(
            "linux-crontab-change",
            Medium,
            "Linux crontab modified",
            "crontab logs recorded scheduled task replacement or deletion.",
            "Verify the task content, executing account, and modification authorization.",
            LinuxText(re(r"(?i)\bcrontab(?:\[\d+\])?\s*:[^\r\n]*\b(?:REPLACE|DELETE)\b")),
        );
        add(
            "linux-ssh-key-change",
            Medium,
            "Linux SSH authorized-keys modification",
            "Logged commands wrote, copied, or modified authorized_keys.",
            "Verify the public key origin, target user, and change authorization.",
            LinuxText(re(r"(?i)(?:\b(?:cp|tee|chmod|chown|sed)\b[^\r\n]*authorized_keys|>>?\s*[^\r\n]*authorized_keys)")),
        );
        add(
            "root-login",
            Medium,
            "Remote root logon",
            "Records show root logging in successfully from a remote source.",
            "Verify the source address, authentication method, and direct root logon authorization.",
            RootLogin,
        );
        add(
            "login-failure",
            Low,
            "Login failure records",
            "Single or scattered login failures were found; high-volume failures within short windows are handled by a separate high-severity rule.",
            "Review the account, source, and failure cause, and correlate any subsequent successful logon.",
            LoginFailure,
        );
        add(
            "ssh-password-login",
            Low,
            "SSH password authentication succeeded",
            "SSH logon succeeded using password authentication.",
            "Verify source, account, and authentication policy; watch for unexpected logons.",
            PasswordLogin,
        );
        r
    })
}

pub(super) fn analyze(report: &mut AnalysisReport, ctx: &ExecutionContext) -> anyhow::Result<()> {
    // Aggregate by rule and source to avoid one finding per routine 401/failure.
    let mut matches: BTreeMap<(usize, &str), Vec<&Record>> = BTreeMap::new();
    for (i, record) in report.records.iter().enumerate() {
        ctx.tick(Stage::Rules, None, i, Some(report.records.len()))?;
        if record.status == ParseStatus::Malformed {
            continue;
        }
        let RecordData::Log(log) = &record.data else {
            continue;
        };
        let context = Context {
            log,
            raw: &record.raw,
            provider: provider(log),
            event_id: field(log, "event_id"),
            uri: field(log, "uri").map(|uri| decoded(&uri.replace('+', " "))),
        };
        for (index, rule) in rules().iter().enumerate() {
            if rule.detector.matches(&context) {
                matches
                    .entry((index, &record.source_id))
                    .or_default()
                    .push(record);
            }
        }
    }
    for ((index, _), records) in matches {
        ctx.check()?;
        let rule = &rules()[index];
        let mut f = finding(
            rule.id,
            rule.severity.clone(),
            rule.title,
            format!(
                "{} Matched {} records from the same source; review in the context of asset purpose and authorized operations.",
                rule.detail,
                records.len()
            ),
            records.iter().map(|r| r.id.clone()).collect(),
            match rule.severity {
                Severity::High => 0.8,
                Severity::Medium => 0.65,
                _ => 0.5,
            },
        );
        f.recommendations = vec![rule.advice.into()];
        report.findings.push(f);
    }
    Ok(())
}
