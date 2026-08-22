from model import Asset, Vulnerability, Finding

if __name__ == "__main__":
    prod_firewall = Asset(
        "SRV-001", 
        "FW01", 
        "192.168.0.3", 
        "Production", 
        True, 
        "Critical", 
        "Critical"
 )

    test_workstation = Asset(
        "WKS-001",
        "PC01",
        "192.168.0.6",
        "Test",
        False,
        "low",
        "Medium"
)
    vulnerability = Vulnerability(
        "CVE-2026-9851",
        7.2,
        "The Booking Package plugin for WordPress is vulnerable to Privilege " 
        "Escalation via Account Takeover in versions up to, and including, 1.7.16. " 
        "This is due to a missing capability check on the 'updateUser' branch of the " 
        "package_app_action AJAX endpoint, where the handler only validates a nonce "
        "and the dispatcher invokes Schedule::updateUser() with the $administrator " 
        "argument hard-coded to 1, bypassing the only owner-restriction check inside " 
        "that function and allowing the target user to be determined solely by " 
        "attacker-supplied input passed directly to wp_update_user(). This makes it " 
        "possible for authenticated attackers, with Editor-level access and above, to " 
        "change the email address and password of any account, including Administrator " 
        "accounts, resulting in a full site takeover.",
        "For each and every data access, ensure that the user has sufficient privilege to access the record that "
        "is being requested. Make sure that the key that is used in the lookup of a specific user's record is not "
        "controllable externally by the user or that any tampering can be detected. Use encryption in order to make "
        "it more difficult to guess other legitimate values of the key or associate a digital signature with the "
        "key so that the server can verify that there has been no tampering.",
        "https://www.wordfence.com/threat-intel/vulnerabilities/id/795c1fd6-137b-4414-8d6b-30053bfb5924?source=cve"
)

finding = Finding(test_workstation, vulnerability)
finding.evaluate()
finding.display_report()
