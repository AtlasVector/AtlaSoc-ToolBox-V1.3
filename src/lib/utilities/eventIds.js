// ─── Windows Event ID reference ────────────────────────────────────────────
// Static, offline table of the Security/System event IDs analysts chase most
// often in triage. Not exhaustive — see Microsoft's Security Auditing docs
// for the full list.
//
// `severity` is a rough triage priority (info / suspicious / critical), not
// a verdict — context (frequency, source, baseline) always matters more than
// the event ID alone. `attack` is the MITRE ATT&CK technique this event is
// most commonly associated with; several IDs are legitimate admin activity
// far more often than they're malicious.

export const WINDOWS_EVENT_IDS = {
  4624: { name: 'An account was successfully logged on', category: 'Logon/Logoff', log: 'Security', severity: 'info', attack: 'T1078 Valid Accounts', keyFields: ['Logon Type', 'Account Name', 'Source Network Address', 'Workstation Name'] },
  4625: { name: 'An account failed to log on', category: 'Logon/Logoff', log: 'Security', severity: 'suspicious', attack: 'T1110 Brute Force', keyFields: ['Account Name', 'Failure Reason', 'Source Network Address', 'Logon Type'] },
  4634: { name: 'An account was logged off', category: 'Logon/Logoff', log: 'Security', severity: 'info', attack: null, keyFields: ['Logon Type', 'Account Name'] },
  4648: { name: 'A logon was attempted using explicit credentials', category: 'Logon/Logoff', log: 'Security', severity: 'suspicious', attack: 'T1078 Valid Accounts', keyFields: ['Account Name', 'Target Server Name', 'Process Name'] },
  4672: { name: 'Special privileges assigned to new logon', category: 'Logon/Logoff', log: 'Security', severity: 'suspicious', attack: 'T1078.003 Valid Accounts: Local Accounts', keyFields: ['Account Name', 'Privileges'] },
  4688: { name: 'A new process has been created', category: 'Process Tracking', log: 'Security', severity: 'info', attack: 'T1059 Command and Scripting Interpreter', keyFields: ['New Process Name', 'Command Line', 'Creator Process Name'] },
  4697: { name: 'A service was installed in the system', category: 'System', log: 'Security', severity: 'suspicious', attack: 'T1543.003 Create or Modify System Process: Windows Service', keyFields: ['Service Name', 'Service File Name', 'Account Name'] },
  4698: { name: 'A scheduled task was created', category: 'Object Access', log: 'Security', severity: 'suspicious', attack: 'T1053.005 Scheduled Task/Job: Scheduled Task', keyFields: ['Task Name', 'Command', 'Author'] },
  4720: { name: 'A user account was created', category: 'Account Management', log: 'Security', severity: 'suspicious', attack: 'T1136.001 Create Account: Local Account', keyFields: ['Account Name', 'Account Domain', 'SAM Account Name'] },
  4722: { name: 'A user account was enabled', category: 'Account Management', log: 'Security', severity: 'info', attack: 'T1098 Account Manipulation', keyFields: ['Account Name', 'Target Account'] },
  4724: { name: 'An attempt was made to reset an account\'s password', category: 'Account Management', log: 'Security', severity: 'suspicious', attack: 'T1098 Account Manipulation', keyFields: ['Account Name', 'Target Account'] },
  4725: { name: 'A user account was disabled', category: 'Account Management', log: 'Security', severity: 'info', attack: null, keyFields: ['Account Name', 'Target Account'] },
  4726: { name: 'A user account was deleted', category: 'Account Management', log: 'Security', severity: 'suspicious', attack: 'T1531 Account Access Removal', keyFields: ['Account Name', 'Target Account'] },
  4732: { name: 'A member was added to a security-enabled local group', category: 'Account Management', log: 'Security', severity: 'critical', attack: 'T1098.007 Account Manipulation: Additional Local or Domain Groups', keyFields: ['Member Name', 'Group Name', 'Account Name'] },
  4738: { name: 'A user account was changed', category: 'Account Management', log: 'Security', severity: 'info', attack: 'T1098 Account Manipulation', keyFields: ['Account Name', 'Changed Attributes'] },
  4740: { name: 'A user account was locked out', category: 'Account Management', log: 'Security', severity: 'suspicious', attack: 'T1110 Brute Force', keyFields: ['Account Name', 'Caller Computer Name'] },
  4756: { name: 'A member was added to a security-enabled universal group', category: 'Account Management', log: 'Security', severity: 'critical', attack: 'T1098.007 Account Manipulation: Additional Local or Domain Groups', keyFields: ['Member Name', 'Group Name', 'Account Name'] },
  5140: { name: 'A network share object was accessed', category: 'Object Access', log: 'Security', severity: 'info', attack: 'T1021.002 Remote Services: SMB/Windows Admin Shares', keyFields: ['Share Name', 'Account Name', 'Source Address'] },
  5145: { name: 'A network share object was checked to see whether client can be granted desired access', category: 'Object Access', log: 'Security', severity: 'info', attack: 'T1021.002 Remote Services: SMB/Windows Admin Shares', keyFields: ['Share Name', 'Relative Target Name', 'Account Name'] },
  1102: { name: 'The audit log was cleared', category: 'Log Tampering', log: 'Security', severity: 'critical', attack: 'T1070.001 Indicator Removal: Clear Windows Event Logs', keyFields: ['Subject Account Name'] },
  7045: { name: 'A service was installed in the system', category: 'Service Control Manager', log: 'System', severity: 'suspicious', attack: 'T1543.003 Create or Modify System Process: Windows Service', keyFields: ['Service Name', 'Service File Name', 'Service Type'] },
  4104: { name: 'PowerShell script block logging (Execute a Remote Command)', category: 'PowerShell Operational', log: 'Microsoft-Windows-PowerShell/Operational', severity: 'suspicious', attack: 'T1059.001 Command and Scripting Interpreter: PowerShell', keyFields: ['Script Block Text', 'Path'] },
};

// Prefix match so results appear while the user is still typing (e.g. "462"
// surfaces 4624 and 4625 before the full ID is entered).
export function searchEventIds(query) {
  const q = String(query).trim();
  if (!q) return [];
  return Object.keys(WINDOWS_EVENT_IDS)
    .filter(key => key.startsWith(q))
    .map(key => ({ id: Number(key), ...WINDOWS_EVENT_IDS[key] }))
    .sort((a, b) => a.id - b.id);
}
