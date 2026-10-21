// Display labels only. Original field keys and values remain in the evidence model.
const eventDataLabels: Record<string, string> = {
  AuthenticationPackageName: "Authentication package name",
  FailureReason: "Failure reason",
  IpAddress: "IP address",
  IpPort: "Network port",
  KeyLength: "Key length",
  LmPackageName: "NTLM package name",
  LogonProcessName: "Logon process name",
  LogonType: "Logon type",
  ProcessId: "Process ID",
  ProcessName: "Process name",
  Status: "Status code",
  SubStatus: "Sub-status code",
  SubjectUserSid: "Subject user SID",
  SubjectUserName: "Subject user name",
  SubjectDomainName: "Subject domain name",
  SubjectLogonId: "Subject logon ID",
  TargetUserSid: "Target user SID",
  TargetUserName: "Target user name",
  TargetDomainName: "Target domain name",
  TargetLogonId: "Target logon ID",
  TargetLinkedLogonId: "Linked target logon ID",
  WorkstationName: "Workstation name",
  LogonGuid: "Logon GUID",
  TransmittedServices: "Transmitted services",
  RestrictedAdminMode: "Restricted admin mode",
  VirtualAccount: "Virtual account",
  ElevatedToken: "Elevated token",
  ImpersonationLevel: "Impersonation level",
  NewProcessId: "New process ID",
  NewProcessName: "New process name",
  ParentProcessName: "Parent process name",
  CommandLine: "Command line",
  TokenElevationType: "Token elevation type",
  MandatoryLabel: "Integrity label",
  PrivilegeList: "Privilege list",
  ObjectServer: "Object server",
  ObjectType: "Object type",
  ObjectName: "Object name",
  HandleId: "Handle ID",
  AccessList: "Access list",
  AccessMask: "Access mask",
  ServiceName: "Service name",
  ServiceFileName: "Service file name",
  ServiceType: "Service type",
  ServiceStartType: "Service start type",
  ServiceAccount: "Service account",
  TaskName: "Task name",
  TaskContent: "Task content",
  TaskContentNew: "New task content",
  SourceAddress: "Source address",
  SourcePort: "Source port",
  DestAddress: "Destination address",
  DestPort: "Destination port",
  Protocol: "Protocol",
  Application: "Application",
};

const systemLabels: Record<string, string> = {
  "Provider.Name": "Event provider",
  "Provider.Guid": "Provider GUID",
  "Provider.EventSourceName": "Event source name",
  EventID: "Event ID",
  "EventID.Qualifiers": "Event qualifiers",
  Version: "Event version",
  Level: "Event level",
  Task: "Task category",
  Opcode: "Opcode",
  Keywords: "Keywords",
  "TimeCreated.SystemTime": "Record time",
  EventRecordID: "Event record ID",
  "Correlation.ActivityID": "Activity ID",
  "Correlation.RelatedActivityID": "Related activity ID",
  "Execution.ProcessID": "Execution process ID",
  "Execution.ThreadID": "Execution thread ID",
  Channel: "Log channel",
  Computer: "Computer name",
  "Security.UserID": "User SID",
};

const commonLabels: Record<string, string> = {
  event_id: "Event ID",
  user: "User",
  client_ip: "Client IP address",
  host: "Host",
  action: "Action",
};

function lookup(labels: Record<string, string>, key: string) {
  return Object.hasOwn(labels, key) ? labels[key] : undefined;
}

export function logFieldLabel(key: string): string {
  const normalized = key.replace(/\.#text$/, "");
  for (const prefix of ["Event.EventData.", "EventData."]) {
    if (normalized.startsWith(prefix)) {
      return lookup(eventDataLabels, normalized.slice(prefix.length)) ?? key;
    }
  }
  for (const prefix of ["Event.System.", "System."]) {
    if (normalized.startsWith(prefix)) {
      const field = normalized
        .slice(prefix.length)
        // EVTX emits XML attributes as #attributes; accept the older
        // _attributes forms too, without leaving an extra path separator.
        .replace(/(?:\.#attributes|\.?_attributes)\./g, ".");
      return lookup(systemLabels, field) ?? key;
    }
  }
  return lookup(commonLabels, key) ?? key;
}
