export type CommandPlatform = "windows" | "linux";
export const commandCategories = [
  { value: "system", label: "System and accounts" },
  { value: "process", label: "Process triage" },
  { value: "network", label: "Network triage" },
  { value: "persistence", label: "Persistence triage" },
  { value: "logs", label: "Log triage" },
  { value: "files", label: "Files and forensics" },
] as const;
export type CommandCategory = (typeof commandCategories)[number]["value"];
export interface ResponseCommand {
  id: string;
  platform: CommandPlatform;
  category: CommandCategory;
  title: string;
  description: string;
  shell: "PowerShell" | "CMD" | "Bash";
  permission: string;
  command: string;
  notes: string;
}
function windows(
  id: string,
  category: CommandCategory,
  title: string,
  description: string,
  command: string,
  notes: string,
  permission = "Standard user; administrators can read more",
  shell: ResponseCommand["shell"] = "PowerShell",
): ResponseCommand {
  return {
    id: `windows-${id}`,
    platform: "windows",
    category,
    title,
    description,
    shell,
    permission,
    command,
    notes,
  };
}
function linux(
  id: string,
  category: CommandCategory,
  title: string,
  description: string,
  command: string,
  notes: string,
  permission = "Standard user",
): ResponseCommand {
  return {
    id: `linux-${id}`,
    platform: "linux",
    category,
    title,
    description,
    shell: "Bash",
    permission,
    command,
    notes,
  };
}

// Windows baseline: 64-bit Windows PowerShell 5.1, Windows 10 / Server 2016+.
// Syntax references: Microsoft Learn Windows commands and PowerShell modules
// (CimCmdlets, NetTCPIP, LocalAccounts, ScheduledTasks, Diagnostics, Utility, Security).
// https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
// https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance
// https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
// Linux references: procps-ng, util-linux, iproute2, lsof, GNU coreutils/findutils,
// Cronie and systemd manuals. Availability is stated per entry; nothing is installed.
// https://man7.org/linux/man-pages/man8/ss.8.html
// https://man7.org/linux/man-pages/man8/lsof.8.html
// https://www.freedesktop.org/software/systemd/man/255/journalctl.html
// https://www.gnu.org/software/coreutils/manual/coreutils.html
export const responseCommands: readonly ResponseCommand[] = [
  windows(
    "system-info",
    "system",
    "Show system information",
    "Show OS version, host name, install time, patches, and other baseline details.",
    "systeminfo",
    "Built-in Windows command. Output may include intranet details; handle retention according to case requirements.",
    "Standard user",
    "CMD",
  ),
  windows(
    "identity",
    "system",
    "Show current identity and privileges",
    "List the current account, group memberships, and token privileges.",
    "whoami /all",
    "Shows the identity of the current terminal; an elevated terminal may differ from a standard one.",
    "Standard user",
    "CMD",
  ),
  windows(
    "local-users",
    "system",
    "Show local user accounts",
    "Check whether accounts are enabled plus last logon and password set times.",
    "Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description",
    "Requires the LocalAccounts module and 64-bit PowerShell; domain controllers have no ordinary local account database.",
  ),
  windows(
    "administrators",
    "system",
    "Show local administrators group members",
    "Check the local Administrators group for unexpected accounts.",
    "Get-LocalGroup -SID 'S-1-5-32-544' | Get-LocalGroupMember",
    "Queries by fixed SID so language-specific group names do not matter; needs the LocalAccounts module and does not apply to domain controllers.",
  ),

  windows(
    "process-command",
    "process",
    "Show process paths and command lines",
    "List process names, PIDs, executable paths, and full command lines.",
    "Get-CimInstance Win32_Process |\n  Select-Object Name, ProcessId, ExecutablePath, CommandLine",
    "Some protected processes may have empty paths and command lines; do not treat a missing field as suspicious by itself.",
  ),
  windows(
    "process-parent",
    "process",
    "Show process parent-child relationships",
    "Show process relations and creation times by parent PID to review unusual launch chains.",
    "Get-CimInstance Win32_Process |\n  Sort-Object ParentProcessId, ProcessId |\n  Select-Object Name, ProcessId, ParentProcessId, CreationDate",
    "This is a snapshot of current processes; parents may have exited and PIDs can be reused, so verify against creation times.",
  ),
  windows(
    "process-service",
    "process",
    "Show services hosted by processes",
    "List running processes and the service names they host.",
    "tasklist /svc",
    "Built-in Windows command; one svchost.exe can host several services.",
    "Standard user; administrators can read more",
    "CMD",
  ),
  windows(
    "process-modules",
    "process",
    "Show modules loaded by a process",
    "Check the DLL paths and file versions loaded by a given process.",
    "$ProcessId = 1234\nGet-Process -Id $ProcessId -Module |\n  Select-Object ModuleName, FileName, FileVersionInfo",
    "Replace 1234 with the target PID. Prefer 64-bit PowerShell; protected processes or cross-bitness access may fail.",
    "Administrator; protected processes may still be unreadable",
  ),

  windows(
    "tcp",
    "network",
    "Show TCP connections",
    "Show connection addresses, ports, states, and the owning process PID.",
    "Get-NetTCPConnection |\n  Sort-Object State, OwningProcess |\n  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess",
    "Requires the NetTCPIP module; OwningProcess can be matched against the process list PIDs.",
  ),
  windows(
    "udp",
    "network",
    "Show UDP endpoints",
    "Show locally bound UDP addresses, ports, and owning PIDs.",
    "Get-NetUDPEndpoint |\n  Select-Object LocalAddress, LocalPort, OwningProcess",
    "Requires the NetTCPIP module; the UDP endpoint list does not provide full remote communication history.",
  ),
  windows(
    "ip-config",
    "network",
    "Show network configuration",
    "Show adapters, IP addresses, default gateways, and DNS servers.",
    "Get-NetIPConfiguration -Detailed",
    "Requires the NetTCPIP module; queries the current configuration only and does not modify adapters or routes.",
    "Standard user",
  ),
  windows(
    "dns-cache",
    "network",
    "Show the DNS cache",
    "Check domain name resolutions recently cached by the host.",
    "Get-DnsClientCache",
    "Requires the DnsClient module; cache entries expire and cannot represent the complete DNS access history.",
    "Standard user",
  ),

  windows(
    "services",
    "persistence",
    "Show service configurations",
    "Check service executable paths, run accounts, start modes, and states.",
    "Get-CimInstance Win32_Service |\n  Select-Object Name, State, StartMode, StartName, PathName",
    "Watch for unexpected paths and accounts; the query never starts, stops, or modifies services.",
  ),
  windows(
    "tasks",
    "persistence",
    "Show scheduled tasks and actions",
    "List scheduled task programs, arguments, and triggers.",
    "Get-ScheduledTask |\n  Select-Object TaskPath, TaskName, State, Actions, Triggers |\n  Format-List",
    "Requires the ScheduledTasks module. Administrators can see more tasks; review Actions and Triggers against the task's purpose.",
  ),
  windows(
    "run-keys",
    "persistence",
    "Show Run registry autostart entries",
    "Query the Run/RunOnce entries of the current user, system, and 32-bit programs.",
    String.raw`$Keys = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($Key in $Keys) {
  if (Test-Path -LiteralPath $Key) {
    Get-ItemProperty -LiteralPath $Key | Format-List
  }
}`,
    "HKCU only covers the account running the terminal; this list does not cover other users or every persistence mechanism.",
  ),
  windows(
    "startup",
    "persistence",
    "Show startup entries",
    "Show startup commands visible through WMI, their users, and configuration locations.",
    "Get-CimInstance Win32_StartupCommand |\n  Select-Object Name, Command, Location, User",
    "Queries Win32_StartupCommand; the result is not an exhaustive list of every autostart mechanism.",
  ),

  windows(
    "login-events",
    "logs",
    "Show logon success and failure events",
    "Query events 4624 and 4625 from the last day to review accounts, sources, and logon types.",
    "Get-WinEvent -FilterHashtable @{\n  LogName = 'Security'; Id = 4624,4625; StartTime = (Get-Date).AddDays(-1)\n} -MaxEvents 200 | Format-List TimeCreated, Id, Message",
    "Adjust AddDays(-1) and MaxEvents as needed. Depends on auditing being enabled and log retention; an empty result does not prove no logon activity.",
    "Administrator or Security log read permission",
  ),
  windows(
    "log-clear",
    "logs",
    "Show audit log clear events",
    "Query event 1102 in the Security log to review clear times and acting identities.",
    "Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 100 |\n  Format-List TimeCreated, Id, Message",
    "1102 indicates a Security log clear; review it together with authorized maintenance and other logs. Log rotation or overwriting may remove records.",
    "Administrator or Security log read permission",
  ),
  windows(
    "service-events",
    "logs",
    "Show service install events",
    "Query event 7045 in the System log to review new service configurations.",
    "Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } -MaxEvents 100 |\n  Format-List TimeCreated, Id, Message",
    "7045 means a service install and does not prove malicious persistence by itself; check the install source, path, and maintenance records.",
  ),
  windows(
    "powershell-events",
    "logs",
    "Show PowerShell script events",
    "Show 4104 script block records from the PowerShell Operational channel.",
    "Get-WinEvent -FilterHashtable @{\n  LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104\n} -MaxEvents 100 | Format-List TimeCreated, Id, Message",
    "Results appear only when script block logging is enabled and the records are retained; a script block may be split across several events.",
  ),

  windows(
    "hash",
    "files",
    "Compute file SHA256",
    "Compute a target file digest for evidence integrity checks and later comparison.",
    String.raw`$TargetPath = 'C:\path\sample.exe'
Get-FileHash -LiteralPath $TargetPath -Algorithm SHA256`,
    "Replace C:\\path\\sample.exe with the target file path. Reads the file only; a hash alone cannot tell whether a file is malicious.",
    "Read permission on the target file",
  ),
  windows(
    "signature",
    "files",
    "Show file digital signatures",
    "Show Authenticode signature status, signers, and certificate details.",
    String.raw`$TargetPath = 'C:\path\sample.exe'
Get-AuthenticodeSignature -LiteralPath $TargetPath | Format-List`,
    "Replace the target path. A valid signature does not mean the file is safe, and unsigned does not mean malicious; review the content and source.",
    "Read permission on the target file",
  ),
  windows(
    "recent-files",
    "files",
    "Find recently modified files",
    "Find files modified within the last day under a given directory.",
    String.raw`$SearchRoot = 'C:\path\directory'
Get-ChildItem -LiteralPath $SearchRoot -File -Recurse -Force |
  Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-1) } |
  Select-Object FullName, Length, CreationTime, LastWriteTime`,
    "Replace the directory and time range; recursing large directories can take time and inaccessible directories raise errors. File times can be altered, so treat them as hints only.",
    "Read permission on the target directory",
  ),
  windows(
    "export-evtx",
    "files",
    "Export the Security EVTX",
    "Export the Security log to an EVTX file for offline analysis.",
    String.raw`wevtutil epl Security "C:\Evidence\Security.evtx" /ow:false`,
    "Prepare the C:\\Evidence directory and replace the output path first; writes a new EVTX, refuses to overwrite an existing target, and never clears the source log. The live log may still change meanwhile.",
    "Administrator or log read plus target directory write permission",
    "CMD",
  ),

  linux(
    "system-info",
    "system",
    "Show OS version",
    "Show kernel, architecture, and distribution identity.",
    "uname -a\ncat /etc/os-release",
    "Requires uname and cat; some older or minimal systems may lack /etc/os-release.",
  ),
  linux(
    "uptime",
    "system",
    "Show boot time and load",
    "Show boot time, uptime, and current load averages.",
    "uptime -s\nuptime",
    "Requires procps-ng uptime; -s may not be supported by BusyBox builds.",
  ),
  linux(
    "accounts",
    "system",
    "Show system account list",
    "Query NSS-visible accounts with UIDs, home directories, and login shells.",
    "getent passwd",
    "Requires getent; results may include directory service accounts such as LDAP and are not limited to /etc/passwd.",
  ),
  linux(
    "logged-in",
    "system",
    "Show currently logged-in users",
    "Show logged-in users, sources, terminals, and current activity.",
    "who -a\nw",
    "Requires GNU coreutils who and procps-ng w; depends on utmp, which containers and some minimal systems may not record.",
  ),

  linux(
    "processes",
    "process",
    "Show process list",
    "Show accounts, PIDs, PPIDs, start times, and full process arguments.",
    "ps -eo user,pid,ppid,lstart,args --forest",
    "Requires procps-ng; --forest may not be supported by BusyBox ps.",
    "Standard user; root can read more process details",
  ),
  linux(
    "process-tree",
    "process",
    "Show process tree",
    "Show process hierarchy, PIDs, and launch arguments.",
    "pstree -ap",
    "Requires psmisc pstree; some process arguments are limited by permissions and /proc mount options.",
    "Standard user; root can read more process details",
  ),
  linux(
    "process-files",
    "process",
    "Show open files of a process",
    "Check the files, devices, and sockets opened by the target process.",
    'PROCESS_ID=1234\nsudo lsof -nP -p "$PROCESS_ID"',
    "Replace 1234 with the target PID; requires lsof and sudo, or root can run lsof directly.",
    "Root; or sudo permission",
  ),
  linux(
    "process-command",
    "process",
    "Show process path and command line",
    "Read the target process executable path and its NUL-separated full arguments.",
    "PROCESS_ID=1234\nsudo readlink -f \"/proc/$PROCESS_ID/exe\"\nsudo cat \"/proc/$PROCESS_ID/cmdline\" | tr '\\0' ' '\nprintf '\\n'",
    "Replace the PID. Requires procfs mounted, coreutils, and sudo; paths disappear after the process exits, and an exe with a deleted marker needs further review.",
    "Process owner or root; the example uses sudo",
  ),

  linux(
    "connections",
    "network",
    "Show current TCP/UDP connections",
    "List current connections and owning processes to review unexpected outbound traffic.",
    "sudo ss -antup",
    "Requires iproute2 and sudo; -p process details are permission-limited and the connection list is not communication history.",
    "Root; or sudo permission",
  ),
  linux(
    "listeners",
    "network",
    "Show listening ports",
    "Check TCP/UDP listening addresses, ports, and owning processes.",
    "sudo ss -lntup",
    "Requires iproute2; whether a 0.0.0.0 or :: listener is reachable from outside also depends on the firewall and network setup.",
    "Root; or sudo permission",
  ),
  linux(
    "ip-route",
    "network",
    "Show addresses and routes",
    "Show adapter addresses plus IPv4 and IPv6 routes.",
    "ip -br address\nip route show\nip -6 route show",
    "Requires iproute2; -br prints compact output and older versions can use ip address show instead.",
  ),
  linux(
    "network-processes",
    "network",
    "Show process network connections",
    "Use open network files to review which processes own which connections.",
    "sudo lsof -nP -i",
    "Requires lsof and sudo; -nP disables name resolution so numeric addresses and ports are kept.",
    "Root; or sudo permission",
  ),

  linux(
    "enabled-services",
    "persistence",
    "Show boot-enabled services",
    "Show service units set to enabled in systemd.",
    "systemctl list-unit-files --type=service --state=enabled --no-pager",
    "Applies to systemd only; enabled does not mean currently running and does not cover static units or other startup mechanisms.",
  ),
  linux(
    "timers",
    "persistence",
    "Show systemd timers",
    "Check timers, their services, and last and next trigger times.",
    "systemctl list-timers --all --no-pager",
    "Applies to systemd only; these are the system manager's timers, and user timers need a separate systemctl --user query.",
  ),
  linux(
    "user-crontab",
    "persistence",
    "Show a user's crontab",
    "Check recurring tasks configured for a given account.",
    'ACCOUNT_NAME=root\nsudo crontab -u "$ACCOUNT_NAME" -l',
    "Replace root with the target account; requires cron/Cronie and sudo. A no crontab message only means the account has no user crontab configured.",
    "Root; or sudo permission",
  ),
  linux(
    "system-cron",
    "persistence",
    "Show system cron configuration",
    "Show the system crontab, cron.d configuration, and recurring script directories.",
    'sudo cat /etc/crontab\nsudo find /etc/cron.d -maxdepth 1 -type f -exec sh -c \'printf "\\n--- %s ---\\n" "$1"; cat -- "$1"\' sh {} \\;\nsudo ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly',
    "Directory layouts vary by distribution and missing paths raise errors; this only reads configuration and lists files, never runs the recurring scripts.",
    "Root; or sudo permission",
  ),

  linux(
    "login-success",
    "logs",
    "Show successful login history",
    "Show login and reboot records stored in wtmp, keeping source addresses.",
    "last -Fai",
    "Requires util-linux last and wtmp; some distributions switched to wtmpdb, and rotation or missing files affect coverage.",
  ),
  linux(
    "login-failure",
    "logs",
    "Show failed login history",
    "Show failed login records stored in btmp.",
    "sudo lastb -Fai",
    "Requires util-linux lastb and btmp; nothing recorded or a missing file does not prove there were no failed logins.",
    "Root; or btmp read permission",
  ),
  linux(
    "ssh-auth",
    "logs",
    "Show SSH authentication logs",
    "Search common authentication log paths for sshd login and authentication records.",
    "sudo grep -E 'sshd.*(Accepted|Failed|Invalid user|authentication failure)' /var/log/auth.log /var/log/secure",
    "Debian/Ubuntu commonly uses auth.log while RHEL-family uses secure; missing paths raise errors. journal-only systems can use journalctl -t sshd; rotated logs need extra checks.",
    "Root; or authentication log read permission",
  ),
  linux(
    "journal-range",
    "logs",
    "Show system logs for a time range",
    "Query the systemd journal between start and end times, printing timezone-aware values.",
    "START_TIME='2026-10-13 00:00:00'\nEND_TIME='2026-10-13 23:59:59'\nsudo journalctl --since \"$START_TIME\" --until \"$END_TIME\" --output=short-iso-precise --no-pager",
    "Replace both time values; without an explicit zone they are interpreted in the target host's local time zone. Requires systemd; older versions can use short-iso instead.",
    "Root; or journal read permission",
  ),

  linux(
    "hash",
    "files",
    "Compute file SHA256",
    "Compute a target file digest for evidence integrity checks and comparison.",
    "TARGET_PATH='/path/to/sample'\nsha256sum -- \"$TARGET_PATH\"",
    "Replace the target path; requires GNU coreutils. Reads the file only, and a hash alone cannot tell maliciousness.",
    "Read permission on the target file",
  ),
  linux(
    "file-stat",
    "files",
    "Show file times and permissions",
    "Show permissions, owner, size, access/modification/metadata-change times, and inode.",
    "TARGET_PATH='/path/to/sample'\nstat -- \"$TARGET_PATH\"",
    "Replace the target path; requires GNU coreutils. ctime is the metadata change time, not the file creation time.",
    "Access permission on the target path",
  ),
  linux(
    "recent-files",
    "files",
    "Find recently modified files",
    "Find regular files modified within the last day under a given directory.",
    "SEARCH_ROOT='/path/to/directory'\nsudo find \"$SEARCH_ROOT\" -xdev -type f -mtime -1 -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\\n'",
    "Replace the search directory; requires GNU findutils. -xdev does not cross file systems and -mtime -1 means the last 24 hours; large directories can take time.",
    "Read permission on the target directory; the example uses sudo",
  ),
  linux(
    "copy-logs",
    "files",
    "Copy logs for retention",
    "Retain selected logs in a fresh forensics directory, preserving file attributes.",
    'SOURCE_LOG=\'/var/log/auth.log\'\nEVIDENCE_DIR=\'/path/to/new-evidence-directory\'\nsudo mkdir -m 700 -- "$EVIDENCE_DIR" &&\n  sudo cp -a --no-clobber -- "$SOURCE_LOG" "$EVIDENCE_DIR/"',
    "Replace the source log and new directory paths. Requires GNU coreutils and sudo; writes into the forensics directory without overwriting existing files and stops if the directory exists. The live log may change during the copy.",
    "Root; or source log read plus target directory write permission",
  ),
];
