"""
Complete MITRE ATT&CK for ICS matrix — all 12 tactics, all 79 top-level
techniques (sub-techniques collapsed into their parent for this view).

Source: https://attack.mitre.org/matrices/ics/ (v19.2)
Used to render the full ATT&CK Matrix dashboard view, with IronLedger's
six demo-narrative techniques highlighted in context.
"""

FULL_ICS_MATRIX = [
    ("Initial Access", [
        ("T0817", "Drive-by Compromise"),
        ("T0819", "Exploit Public-Facing Application"),
        ("T0866", "Exploitation of Remote Services"),
        ("T0822", "External Remote Services"),
        ("T0883", "Internet Accessible Device"),
        ("T0886", "Remote Services"),
        ("T0847", "Replication Through Removable Media"),
        ("T0848", "Rogue Master"),
        ("T0865", "Spearphishing Attachment"),
        ("T0862", "Supply Chain Compromise"),
        ("T0864", "Transient Cyber Asset"),
        ("T0860", "Wireless Compromise"),
    ]),
    ("Execution", [
        ("T0895", "Autorun Image"),
        ("T0858", "Change Operating Mode"),
        ("T0807", "Command-Line Interface"),
        ("T0871", "Execution through API"),
        ("T0823", "Graphical User Interface"),
        ("T0874", "Hooking"),
        ("T0821", "Modify Controller Tasking"),
        ("T0834", "Native API"),
        ("T0853", "Scripting"),
        ("T0863", "User Execution"),
    ]),
    ("Persistence", [
        ("T1694", "Insecure Credentials"),
        ("T1693", "Modify Firmware"),
        ("T0889", "Modify Program"),
        ("T0873", "Project File Infection"),
        ("T0859", "Valid Accounts"),
    ]),
    ("Privilege Escalation", [
        ("T0890", "Exploitation for Privilege Escalation"),
        ("T0874", "Hooking"),
    ]),
    ("Evasion", [
        ("T0858", "Change Operating Mode"),
        ("T0820", "Exploitation for Evasion"),
        ("T0872", "Indicator Removal on Host"),
        ("T0849", "Masquerading"),
        ("T0851", "Rootkit"),
        ("T0894", "System Binary Proxy Execution"),
        ("T1692", "Unauthorized Message"),
    ]),
    ("Discovery", [
        ("T0840", "Network Connection Enumeration"),
        ("T0842", "Network Sniffing"),
        ("T0846", "Remote System Discovery"),
        ("T0888", "Remote System Information Discovery"),
        ("T0887", "Wireless Sniffing"),
    ]),
    ("Lateral Movement", [
        ("T0866", "Exploitation of Remote Services"),
        ("T1694", "Insecure Credentials"),
        ("T0867", "Lateral Tool Transfer"),
        ("T0843", "Program Download"),
        ("T0886", "Remote Services"),
        ("T0859", "Valid Accounts"),
    ]),
    ("Collection", [
        ("T0830", "Adversary-in-the-Middle"),
        ("T0802", "Automated Collection"),
        ("T0811", "Data from Information Repositories"),
        ("T0893", "Data from Local System"),
        ("T0868", "Detect Operating Mode"),
        ("T0877", "I/O Image"),
        ("T0801", "Monitor Process State"),
        ("T0861", "Point & Tag Identification"),
        ("T0845", "Program Upload"),
        ("T0852", "Screen Capture"),
        ("T0887", "Wireless Sniffing"),
    ]),
    ("Command and Control", [
        ("T0885", "Commonly Used Port"),
        ("T0884", "Connection Proxy"),
        ("T0869", "Standard Application Layer Protocol"),
    ]),
    ("Inhibit Response Function", [
        ("T0800", "Activate Firmware Update Mode"),
        ("T0878", "Alarm Suppression"),
        ("T1695", "Block Communications"),
        ("T1691", "Block Operational Technology Message"),
        ("T0892", "Change Credential"),
        ("T0809", "Data Destruction"),
        ("T0814", "Denial of Service"),
        ("T0815", "Denial of View"),
        ("T0816", "Device Restart/Shutdown"),
        ("T0835", "Manipulate I/O Image"),
        ("T0838", "Modify Alarm Settings"),
        ("T1693", "Modify Firmware"),
        ("T0851", "Rootkit"),
        ("T0881", "Service Stop"),
        ("T0855", "Unauthorized Command Message"),
    ]),
    ("Impair Process Control", [
        ("T0806", "Brute Force I/O"),
        ("T1693", "Modify Firmware"),
        ("T0836", "Modify Parameter"),
        ("T0831", "Manipulation of Control"),
        ("T1692", "Unauthorized Message"),
    ]),
    ("Impact", [
        ("T0879", "Damage to Property"),
        ("T0813", "Denial of Control"),
        ("T0815", "Denial of View"),
        ("T0826", "Loss of Availability"),
        ("T0827", "Loss of Control"),
        ("T0828", "Loss of Productivity and Revenue"),
        ("T0837", "Loss of Protection"),
        ("T0880", "Loss of Safety"),
        ("T0829", "Loss of View"),
        ("T0831", "Manipulation of Control"),
        ("T0832", "Manipulation of View"),
        ("T0882", "Theft of Operational Information"),
        ("T0888", "Remote System Information Discovery"),
    ]),
]


def is_hit(technique_id: str, hits: set[str]) -> bool:
    """A sub-technique hit like 'T1692.001' highlights its parent 'T1692' in
    this top-level matrix view."""
    if technique_id in hits:
        return True
    return any(h == technique_id or h.startswith(technique_id + ".") for h in hits)
