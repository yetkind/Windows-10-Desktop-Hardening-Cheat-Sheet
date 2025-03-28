# Windows 10 Desktop Hardening Cheat Sheet

This cheat sheet provides detailed steps to harden a Windows 10 desktop.


## 1. Account Security

| Step | Action | Details |
| :--- | :--- | :--- |
| 1.1 | Disable Guest Account | Open `lusrmgr.msc` (Local Users and Groups), navigate to `Users`, right-click "Guest," and select "Properties." Check "Account is disabled." This prevents unauthorized access. |
| 1.2 | Rename Administrator Account | Open `lusrmgr.msc`, rename the built-in Administrator account to a non-standard name. This obscures the account from automated attacks. |
| 1.3 | Use Standard User Accounts | Create and use standard user accounts for daily tasks. Reserve the renamed Administrator account for system administration only. This limits the impact of malware or accidental changes. |
| 1.4 | Enable Account Lockout | In `gpedit.msc` (Group Policy Editor), navigate to `Computer Configuration\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`. Set lockout threshold, duration, and reset counter to prevent brute-force attacks. Recommended settings: Threshold: 5-10 invalid attempts, Duration: 30-60 minutes, Reset counter: same as duration. |
| 1.5 | Disable interactive logon of the built in administrator | In gpedit.msc, Navigate to Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options. Enable "Accounts: Limit local account use of blank passwords to console logon only" and "Accounts: Rename guest account". |

## 2. Password Policies

| Step | Action | Details |
| :--- | :--- | :--- |
| 2.1 | Enforce Strong Passwords | In `gpedit.msc`, navigate to `Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy`. Set minimum password length (12+ characters), complexity (uppercase, lowercase, numbers, symbols), and maximum password age (90 days or less). |
| 2.2 | Use Password Manager | Implement a password manager (e.g., Bitwarden, KeePass) to encourage users to create and store strong, unique passwords. Educate users on its safe usage. |
| 2.3 | Disable Password Storage | Disable password storage in Windows Credential Manager and browser settings. This prevents credentials from being stored in plain text or easily accessible formats. |
| 2.4 | Enable Multi-Factor Authentication (MFA) | Use Windows Hello for Business, smart cards, or other MFA solutions wherever possible. MFA adds an extra layer of security. |
| 2.5 | Prevent Password Reuse | In `gpedit.msc`, navigate to `Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy`. Set "Enforce password history" to a value greater than 0, such as 24. |

## 3. User Account Control (UAC)

| Step | Action | Details |
| :--- | :--- | :--- |
| 3.1 | Set UAC to Always Notify | In `secpol.msc` (Local Security Policy) or `gpedit.msc`, navigate to `Security Settings\Local Policies\Security Options`. Set "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Elevate without prompting." Set "User Account Control: Notify me only when programs try to make changes to my computer" to "Always notify." |
| 3.2 | Protect Administrator Approval Mode | Ensure UAC protects administrator approval mode to prevent malicious software from bypassing UAC prompts. |

## 4. Firewall Configuration

| Step | Action | Details |
| :--- | :--- | :--- |
| 4.1 | Enable Windows Firewall | Ensure Windows Firewall is enabled for all network profiles (domain, private, public). |
| 4.2 | Block Inbound Connections | Block all unsolicited inbound connections by default. Only allow necessary ports and applications. |
| 4.3 | Allow Necessary Outbound Connections | Configure outbound rules as needed, limiting applications to specific ports and protocols. |
| 4.4 | Enable Firewall Logging | Enable firewall logging to monitor network activity. Review logs regularly for suspicious connections. |
| 4.5 | Configure advanced security settings | In the windows firewall with advanced security console, configure IPsec settings, connection security rules, and monitoring. |

## 5. Windows Updates

| Step | Action | Details |
| :--- | :--- | :--- |
| 5.1 | Enable Automatic Updates | Configure Windows Update to automatically download and install updates. |
| 5.2 | Install Updates Regularly | Ensure updates are installed promptly to patch vulnerabilities. |
| 5.3 | Configure Active Hours | Set active hours to prevent updates from interrupting work. |
| 5.4 | Use WSUS or WUfB | Implement Windows Server Update Services (WSUS) or Windows Update for Business (WUfB) for centralized update management. |

## 6. Antivirus and Anti-malware

| Step | Action | Details |
| :--- | :--- | :--- |
| 6.1 | Install Reputable Antivirus | Install a reputable antivirus solution (e.g., Windows Defender, third-party) and keep it updated. |
| 6.2 | Enable Real-time Protection | Enable real-time protection and scanning to prevent malware infections. |
| 6.3 | Perform Regular Scans | Schedule regular full system scans to detect and remove threats. |
| 6.4 | Enable Ransomware Protection | Use Windows Defender's Controlled Folder Access or other ransomware protection features. |
| 6.5 | Use Anti-Exploit tools | Install and use anti-exploit tools such as EMET (if applicable), or the exploit protection built into windows. |

## 7. BitLocker Encryption

| Step | Action | Details |
| :--- | :--- | :--- |
| 7.1 | Enable BitLocker | Enable BitLocker drive encryption for all drives, including system and data drives. |
| 7.2 | Store Recovery Keys Securely | Store BitLocker recovery keys securely (e.g., Active Directory, external drive, printed copy in a safe). |
| 7.3 | Enable BitLocker for Removable Drives | Enable BitLocker To Go for removable drives to protect sensitive data. |
| 7.4 | Enable pre-boot authentication | Configure BitLocker to require a PIN or startup key before Windows loads. |

## 8. Group Policy Hardening

| Step | Action | Details |
| :--- | :--- | :--- |
| 8.1 | Disable Autorun | In `gpedit.msc`, navigate to `Computer Configuration\Administrative Templates\Windows Components\AutoPlay Policies`. Disable AutoPlay for all drives. |
| 8.2 | Restrict Removable Storage Access | In `gpedit.msc`, navigate to `Computer Configuration\Administrative Templates\System\Removable Storage Access`. Deny read and write access to removable storage devices. |
| 8.3 | Disable Unnecessary Features | Disable unnecessary Windows features (e.g., remote assistance, remote registry, telnet client). |
| 8.4 | Configure Security Options | Configure security options like interactive logon messages, shutdown behavior, and network security. |
| 8.5 | Software Installation Restrictions | Use Software Restriction Policies or AppLocker to restrict software installations to administrators only. |
| 8.6 | Disable SMBv1 | Disable SMBv1 due to known security vulnerabilities. |
| 8.7 | Restrict anonymous enumeration of SAM accounts and shares | In gpedit.msc, navigate to Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options. Change "Network access: Allow anonymous SID/Name translation" and "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to disabled. |

## 9. Disable Unnecessary Services

| Step | Action | Details |
| :--- | :--- | :--- |
| 9.1 | Review Running Services | Review and disable unnecessary services using `services.msc`. Research each service before disabling it. |
| 9.2 | Be Cautious | Be cautious when disabling services, as some are essential for system functionality. |
| 9.3 | Configure service startup types | configure service startup types to manual or disabled for unneeded services. |

## 10. Software Restriction Policies/AppLocker

| Step | Action | Details |
| :--- | :--- | :--- |
| 10.1 | Implement AppLocker | Use AppLocker to control which applications can run on the system. |
| 10.2 | Create Whitelists | Create whitelists of approved applications based on publisher, path, or file hash. |
| 10.3 | Block Unwanted Software | Block execution of unwanted software, including executables, scripts, and Windows Installer packages. |
| 10.4 | Use default rules as a base | Use the default rules provided by applocker, and then modify them to your needs. |

## 11. Browser Hardening

| Step | Action | Details |
| :--- | :--- | :--- |
| 11.1 | Use Secure Browser | Use a secure browser (e.g., Firefox with hardened settings, Chrome with security extensions). |
| 11.2 | Disable Unnecessary Plugins | Disable or remove unnecessary browser plugins (e.g., Flash, Java). |
| 11.3 | Enable Tracking Protection | Enable tracking protection and ad blockers to prevent online tracking. |
| 11.4 | Configure Security Settings | Adjust browser security settings (e.g., disable JavaScript, enable HTTPS-Only mode, disable third-party cookies). |
| 11.5 | Use security extensions | Use security related browser extensions such as HTTPS everywhere, Privacy Badger, and NoScript. |

## 12. Event Log Auditing

| Step | Action | Details |
| :--- | :--- | :--- |
| 12.1 | Enable Audit Policies | Enable audit policies for logon events, account management, and object access using `gpedit.msc`. |
| 12.2 | Review Event Logs Regularly | Review event logs regularly for suspicious activity. Use tools like Event Viewer or PowerShell. |
| 12.3 | Forward Logs to SIEM | Forward event logs to a Security Information and Event Management (SIEM) system for centralized logging and analysis. |
| 12.4 | Configure log size and retention | Configure event log sizes and retention policies to ensure adequate logging. |

## 13. Device Guard and Credential Guard

| Step | Action | Details |
| :--- | :--- | :--- |
| 13.1 | Enable Device Guard | Implement Device Guard for code integrity enforcement, preventing unsigned or untrusted code from running. |
| 13.2 | Enable Credential Guard | Enable Credential Guard to protect credentials by isolating them in a virtualized environment. |
| 13.3 | Requires Specific Hardware | Note: These features require specific hardware and Windows editions. |
| 13.4 | Configure HVCI | Enable Hypervisor-protected code integrity (HVCI). |

## 14. Remove Unnecessary Software

| Step | Action | Details |
| :--- | :--- | :--- |
| 14.1 | Uninstall Unused Applications | Uninstall unnecessary software to reduce the attack surface. |
| 14.2 | Review Pre-installed Software | Remove pre-installed bloatware and unnecessary applications. |
| 14.3 | Audit installed programs | Regularly audit installed programs to identify and remove unneeded software. |

## 15. Registry Hardening

| Step | Action | Details |
| :--- | :--- | :--- |
| 15.1 | Disable LM and NTLMv1 | Disable LM and NTLMv1 authentication in the registry. |
| 15.2 | Disable remote registry access | disable remote registry access to prevent unwanted remote manipulation. |
| 15.3 | Secure RPC communication | Secure RPC communication by configuring authentication levels. |
| 15.4 | Restrict anonymous access to named pipes and shares | Restrict anonymous access to named pipes and shares by modifying registry values. |

## 16. Network Security

| Step | Action | Details |
| :--- | :--- | :--- |
| 16.1 | Disable NetBIOS over TCP/IP | Disable NetBIOS over TCP/IP to prevent NetBIOS name resolution attacks. |
| 16.2 | Use DNSSEC | Use DNSSEC to protect against DNS spoofing and cache poisoning. |
| 16.3 | Configure IPSec | Configure IPsec to secure network communications. |
| 16.4 | Use a VPN | Use a virtual private network (VPN) for secure remote access. |
| 16.5 | Use WPA3 | Use WPA3 encryption for wireless networks. |

## 17. Storage Security

| Step | Action | Details |
| :--- | :--- | :--- |
| 17.1 | Encrypt sensitive data | Encrypt sensitive data stored on local drives or removable media. |
| 17.2 | Use access control lists (ACLs) | Use access control lists (ACLs) to control access to files and folders. |
| 17.3 | Secure temporary files | Secure temporary files by configuring appropriate permissions. |
| 17.4 | Use EFS | Use Encrypting File System (EFS) to encrypt individual files and folders. |


-------

## Full Checklist

* **Update OS & Applications:**
  * [ ] Ensure Windows 10 is updated to the latest version.
  * [ ] Update all installed applications.
* **Configure Windows Firewall:**
  * [ ] Enable and properly configure Windows Firewall.
  * [ ] Block unnecessary inbound and outbound traffic.
* **Audit User Accounts:**
  * [ ] Disable or remove unnecessary user accounts.
  * [ ] Rename the default Administrator account.
  * [ ] Enforce strong password policies.
  * [ ] Setup account lockout policies.
* **Harden Local Security Policies:**
  * [ ] Configure security options to enhance system security.
  * [ ] Restrict anonymous enumeration.
* **Set Filesystem Permissions:**
  * [ ] Configure NTFS permissions to limit access to sensitive files and folders.
* **Implement AppLocker/Software Restriction Policies:**
  * [ ] Control which applications can run on the system.
* **Enable BitLocker Encryption:**
  * [ ] Encrypt system and data drives.
  * [ ] Securely store recovery keys.
* **Event Log Auditing:**
  * [ ] Enable and configure event log auditing.
  * [ ] Regularly review event logs.
* **Disable Unnecessary Services:**
  * [ ] Review and disable unnecessary Windows services.
* **Browser Hardening:**
  * [ ] Harden browser security settings.
  * [ ] Install security extensions.
* **Anti-Virus and Anti-Malware:**
  * [ ] Install and configure a reputable antivirus/antimalware solution.
  * [ ] Enable real time protection.
* **Remove Unnecessary Software:**
  * [ ] Uninstall unused applications.

## Detailed Steps and Commands

| Step | Action | Details/Commands |
| :--- | :--- | :--- |
| **Update OS & Applications** | Ensure Windows 10 is updated. | `Settings > Update & Security > Windows Update > Check for updates` |
| | Update Applications | Update all installed applications manually or through their built-in update mechanisms. |
| **Configure Windows Firewall** | Enable and configure Windows Firewall. | `Control Panel > Windows Defender Firewall > Turn Windows Defender Firewall on or off` |
| | Block unnecessary traffic. | `Windows Firewall with Advanced Security (wf.msc)`: Configure inbound and outbound rules. |
| **Audit User Accounts** | Disable unnecessary accounts. | `lusrmgr.msc`: Disable guest accounts, unused accounts. |
| | Rename Administrator account. | `lusrmgr.msc`: Rename the built-in Administrator account. |
| | Enforce strong passwords. | `gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy` |
| | Account lockout policies. | `gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy` |
| **Harden Local Security Policies** | Configure security options. | `secpol.msc` or `gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options` |
| | Restrict anonymous enumeration | `secpol.msc` or `gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options` : Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled |
| **Set Filesystem Permissions** | Configure NTFS permissions. | Right-click on folders > Properties > Security tab: Set appropriate permissions. |
| **Implement AppLocker/SRP** | Control application execution. | `secpol.msc` or `gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker` or `Software Restriction Policies` |
| **Enable BitLocker Encryption** | Encrypt drives. | `Control Panel > BitLocker Drive Encryption` |
| | Secure recovery keys. | Store recovery keys in a safe location. |
| **Event Log Auditing** | Enable event log auditing. | `secpol.msc` or `gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Local Policies > Audit Policy` |
| | Review event logs. | `eventvwr.msc` |
| **Disable Unnecessary Services** | Disable services. | `services.msc`: Review and disable unnecessary services. |
| **Browser Hardening** | Harden browser settings. | Adjust browser security settings (e.g., disable JavaScript, cookies, etc.). |
| | Install security extensions. | Install extensions like HTTPS Everywhere, Privacy Badger. |
| **Anti-Virus and Anti-Malware** | Install and configure AV/AM. | Install and update a reputable antivirus/antimalware solution. |
| | Enable real time protection. | Configure real time protection and regular scans. |
| **Remove Unnecessary Software** | Uninstall unused applications. | `Control Panel > Programs > Programs and Features` or `Settings > Apps > Apps & features` |

## Resources

* **CIS Benchmarks:** The Center for Internet Security (CIS) provides hardening benchmarks for Windows 10. These are highly regarded industry best practices. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* **Microsoft Security Documentation:** Official Microsoft documentation on Windows security features. [Microsoft Security Docs](https://docs.microsoft.com/en-us/windows/security/)
* **NIST National Vulnerability Database (NVD):** A database of known vulnerabilities. [NVD Website](https://nvd.nist.gov/)
* **SANS Institute:** Provides security training and resources. [SANS Institute Website](https://www.sans.org/)
* **Microsoft Docs: Group Policy:** Microsoft documentation on Group Policy settings. [Microsoft Docs: Group Policy](https://docs.microsoft.com/en-us/windows-server/group-policy/)
* **Microsoft Docs: AppLocker:** Microsoft documentation on AppLocker. [Microsoft Docs: AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/applocker/applocker-overview)
* **Microsoft Docs: Bitlocker:** Microsoft documentation on Bitlocker. [Microsoft Docs: Bitlocker](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview)
* **Microsoft Docs: Windows Firewall with Advanced Security:** Microsoft documentation on Windows Firewall advanced settings. [Windows Firewall with Advanced Security](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security)

This cheat sheet covers essential baseline hardening steps for Windows 10. Adapt these steps to your specific environment and security requirements.
It is basic so there are many things can be added for different purposes, Contributions welcome on GitHub! Enjoy! - Yetkin
