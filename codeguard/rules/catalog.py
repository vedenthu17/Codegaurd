"""Rule catalogs (data, not logic), written by the CodeGuard team from the
category definitions, MITRE ATT&CK technique descriptions (T1552 credentials
in files, T1053/T1543/T1546/T1547/T1548 persistence & privilege escalation,
T1485/T1561 destruction, T1048 exfiltration, T1195 supply chain) and common
OS knowledge. Nothing here is copied from a public detection dataset."""
from __future__ import annotations

import re

_I = re.I

# --- secret_access ---------------------------------------------------------
CREDENTIAL_PATHS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.aws/(?:credentials|config)\b", _I), "AWS credentials file"),
    (re.compile(r"\.ssh/(?:id_[a-z0-9_]+|identity)(?!\.pub)\b", _I), "SSH private key"),
    (re.compile(r"(?:^|[/\\])id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub)\b", _I), "SSH private key"),
    (re.compile(r"\.docker/config\.json", _I), "Docker registry auth"),
    (re.compile(r"\.kube/config\b", _I), "Kubernetes kubeconfig"),
    (re.compile(r"(?:^|[/\\~])\.netrc\b|\b_netrc\b", _I), ".netrc credentials"),
    (re.compile(r"\.git-credentials\b", _I), "git credential store"),
    (re.compile(r"(?:^|[/\\~])\.(?:npmrc|pypirc|pgpass|s3cfg|boto|vault-token|my\.cnf)\b", _I), "tool credential file"),
    (re.compile(r"/etc/(?:shadow|gshadow|master\.passwd)\b", _I), "system password hashes"),
    (re.compile(r"(?:^|[/\\])\.env(?:\.(?:local|prod|production|dev|staging))?$", _I), "dotenv secrets file"),
    (re.compile(r"\.config/gcloud/(?:credentials|application_default_credentials|access_tokens|legacy_credentials)", _I), "gcloud credentials"),
    (re.compile(r"\.azure/(?:accessTokens|msal_token_cache|azureProfile)", _I), "Azure CLI tokens"),
    (re.compile(r"/var/run/secrets/kubernetes\.io/serviceaccount", _I), "Kubernetes service-account token"),
    (re.compile(r"/proc/(?:self|\d+|\*)/environ\b", _I), "process environment dump"),
    (re.compile(r"(?:Login Data|Local State|key[34]\.db|logins\.json|cookies\.sqlite|Cookies)$", _I), "browser credential store"),
    (re.compile(r"\.gnupg/(?:private-keys|secring)", _I), "GPG private keys"),
    (re.compile(r"\.terraform\.d/credentials", _I), "Terraform credentials"),
    (re.compile(r"(?:service[-_]?account|client[-_]?secret)[\w-]*\.json$", _I), "cloud service-account key"),
    (re.compile(r"\bwallet\.dat\b|\.electrum/wallets|keystore/UTC--", _I), "crypto wallet"),
    (re.compile(r"Library/Keychains|login\.keychain", _I), "macOS keychain"),
    (re.compile(r"\\Microsoft\\(?:Credentials|Protect)\\|\bSAM\b.*\\config\\|lsass", _I), "Windows credential store"),
]

# --- persistence_or_privesc --------------------------------------------------
PERSISTENCE_PATHS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/etc/sudoers(?:\.d)?\b", _I), "sudoers (privilege grant)"),
    (re.compile(r"/etc/cron(?:tab|\.d|\.daily|\.hourly|\.weekly|\.monthly)?\b|/var/spool/cron", _I), "cron schedule"),
    (re.compile(r"/(?:etc|lib|usr/lib)/systemd/(?:system|user)\b|\.config/systemd/user", _I), "systemd unit"),
    (re.compile(r"/etc/init\.d/|/etc/rc\.local\b|/etc/rc\d\.d/", _I), "init script"),
    (re.compile(r"/etc/profile(?:\.d)?\b|/etc/bash\.bashrc|/etc/environment\b", _I), "global shell profile"),
    (re.compile(r"(?:^|[/\\~])\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zlogin|cshrc|config/fish/config\.fish)\b", _I), "user shell profile"),
    (re.compile(r"/etc/ld\.so\.preload\b", _I), "dynamic-linker preload"),
    (re.compile(r"\.ssh/authorized_keys2?\b", _I), "SSH authorized_keys"),
    (re.compile(r"Library/Launch(?:Agents|Daemons)|/System/Library/LaunchDaemons", _I), "launchd job"),
    (re.compile(r"/etc/(?:passwd|group)\b", _I), "account database"),
    (re.compile(r"Start Menu\\Programs\\Startup|\\Startup\\", _I), "Windows Startup folder"),
    (re.compile(r"CurrentVersion\\(?:Run|RunOnce|Winlogon|Policies\\Explorer\\Run)", _I), "Windows Run key"),
    (re.compile(r"/etc/xdg/autostart|\.config/autostart", _I), "XDG autostart"),
    (re.compile(r"\.git/hooks/", _I), "git hook"),
    (re.compile(r"/etc/pam\.d/|/etc/ssh/sshd_config", _I), "authentication config"),
    (re.compile(r"/etc/security/|/etc/polkit", _I), "authorization policy"),
]

# Paths that must never be the target of recursive deletion / overwrite.
CRITICAL_DELETE_TARGETS = re.compile(
    r"""^(?:/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|/home(?:/\*)?|/root|/etc|/var|/usr|/boot|/bin|/sbin|/lib|/opt|/srv
         |/dev/(?:sd[a-z]|nvme\d|hd[a-z]|xvd[a-z]|disk\d|mmcblk\d)\S*|[A-Za-z]:\\?(?:\\\*)?|[A-Za-z]:\\Windows.*
         |\.|\./|\*|\.\*|\./\*|/(?:etc|var|usr|home|opt|srv|boot|lib|bin|sbin|root|mnt|data)/?\*?)$""",
    re.X,
)
BLOCK_DEVICE = re.compile(r"^/dev/(?:sd[a-z]|nvme\d+n\d+|hd[a-z]|xvd[a-z]|vd[a-z]|disk\d+|mmcblk\d+|md\d+|mapper/)", _I)

# --- ssrf_network_exfil / data_exfiltration ---------------------------------
METADATA_HOSTS = {
    "169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200",
    "metadata.google.internal", "metadata", "metadata.azure.com", "instance-data",
    "instance-data.ec2.internal",
}
DANGEROUS_SCHEMES = {"gopher", "dict", "file", "ldap", "ldaps", "tftp", "jar", "netdoc", "smb", "sftp", "expect", "phar"}
INTERNAL_HOST_SUFFIXES = (".internal", ".local", ".localdomain", ".lan", ".intranet", ".corp", ".svc", ".cluster.local", ".home.arpa")
INTERNAL_SERVICE_PORTS = {6379, 11211, 2375, 2376, 9200, 5984, 27017, 8500, 2379, 10250, 5432, 3306, 9000, 15672}

# Third-party drop points commonly used to receive exfiltrated data.
EXFIL_SERVICES = re.compile(
    r"webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|pastebin\.com|paste\.ee|hastebin"
    r"|transfer\.sh|file\.io|0x0\.st|termbin|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot"
    r"|hooks\.slack\.com|burpcollaborator|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|canarytokens"
    r"|dnslog\.cn|ceye\.io|requestcatcher|beeceptor|mockbin|anonfiles|gofile\.io|mega\.nz",
    _I,
)
# Host labels that advertise hostile intent (placeholder domains used in
# attack write-ups: evil.*, attacker.*, c2.*, exfil.*, ...). Weak signal.
HOSTILE_HOST_LABEL = re.compile(r"(?:^|[.-])(?:evil|attacker|attack|malicious|malware|c2|cnc|exfil|exfiltrate|stealer|payload|hacker|pwn|backdoor|botnet|collector|dropper)(?:[.-]|$)", _I)

# Sensitive data names: environment keys / variables that carry secrets.
SECRET_NAME = re.compile(r"(?:pass(?:wd|word)?|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|credential|auth|session|cookie|bearer|jwt|signing)", _I)

# --- dependency_risk ---------------------------------------------------------
TRUSTED_INDEXES = re.compile(r"^https?://(?:pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|registry\.yarnpkg\.com|test\.pypi\.org)(?:/|$)", _I)
