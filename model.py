import re

class Asset:
    def __init__(
        self, 
        asset_id,  
        hostname,  
        ip_address,  
        environment,   #Test or Production
        internet_exposed, #True or False
        business_impact,  #Low, Medium, High or Critical
        operations_impact   #Low, Medium, High or Critical
):
        self.asset_id = asset_id
        self.hostname = hostname
        self.ip_address = ip_address
        allowed_environments = ["Production", "Test"]
        environment = environment.title()
        if environment not in allowed_environments:
            raise ValueError("Environment must be Production or Test")
        self.environment = environment
        self.internet_exposed = internet_exposed
        allowed_impacts = ["Low", "Medium", "High", "Critical"]
        business_impact = business_impact.title()
        if business_impact not in allowed_impacts:
            raise ValueError("Business impact must be Low, Medium, High, or Critical")
        self.business_impact = business_impact
        allowed_impacts = ["Low", "Medium", "High", "Critical"]
        operations_impact = operations_impact.title()
        if operations_impact not in allowed_impacts:
            raise ValueError("Business impact must be Low, Medium, High, or Critical")
        self.operations_impact = operations_impact
       
    def calculate_environmental_adjustment(self):
        adjustment = 0

        if self.internet_exposed:
            adjustment += 0.5
        if self.operations_impact == "Critical":
            adjustment += 1.5
        elif self.operations_impact == "High":
            adjustment += 1.0
        elif self.operations_impact == "Medium":
            adjustment += 0.5
        if self.business_impact == "Critical":
            adjustment += 1.5
        elif self.business_impact == "High":
            adjustment += 1.0
        elif self.business_impact == "Medium":
            adjustment += 0.5
        if self.environment == "Test":
            adjustment -= 1

        return adjustment   

    
class Vulnerability:
    def __init__(
        self,
        cve,
        cvss_score,
        vulnerability_description,
        vendor_recommendation,
        evidence
):

        cve_pattern = r"^CVE-\d{4}-\d+$"
        if not re.match(cve_pattern, cve):
            raise ValueError("CVE format must be CVE-YYYY-NNNN")
        self.cve = cve
        if cvss_score < 0 or cvss_score > 10:
            raise ValueError("CVSS score must be between 0 and 10")
        self.cvss_score = cvss_score
        self.vulnerability_description = vulnerability_description
        self.vendor_recommendation = vendor_recommendation
        self.evidence = evidence

class Finding:
    def __init__(self, asset, vulnerability):

        self.asset = asset
        self.vulnerability = vulnerability
        self.adjusted_risk_score = None
        self.adjusted_priority = None
        self.reasoning = None
        self.suggested_remediation = None
        self.performed_mitigation = None
        self.status = "Open"

    def calculate_adjusted_risk_score(self):
        original_score = self.vulnerability.cvss_score
        adjustment = self.asset.calculate_environmental_adjustment()

        raw_score = original_score + adjustment
        self.adjusted_risk_score = max(0, min(raw_score, 10))
        return self.adjusted_risk_score

    def determine_priority(self):
        if self.adjusted_risk_score is None:
            self.calculate_adjusted_risk_score()
        if self.adjusted_risk_score == 10:
            self.adjusted_priority = "Critical"
        elif self.adjusted_risk_score >= 8:
            self.adjusted_priority = "High"
        elif self.adjusted_risk_score >= 5:
            self.adjusted_priority = "Medium"
        else:
            self.adjusted_priority = "Low"

        return self.adjusted_priority

    def evaluate(self):
        self.calculate_adjusted_risk_score()
        self.determine_priority()
    
    def generate_reasoning(self):
        reasons = []
        if self.asset.internet_exposed:
            reasons.append("Internet Facing Asset (+0.5)")
        if self.asset.operations_impact == "Critical":
            reasons.append("Critical Operations Impact (+1.5)")
        elif self.asset.operations_impact == "High":
            reasons.append("High Operations Impact (+1.0)")
        elif self.asset.operations_impact == "Medium":
            reasons.append("Medium Operations Impact (+0.5)")
        if self.asset.business_impact == "Critical":
            reasons.append("Critical Business Impact (+1.5)")
        elif self.asset.business_impact == "High":
            reasons.append("High Business Impact (+1.0)")
        elif self.asset.business_impact == "Medium":
            reasons.append("Medium Business Impact (+0.5)")
        if self.asset.environment == "Test":
            reasons.append("Test Environment (-1.0)")

        return reasons

    def generate_suggested_remediation(self):
        self.suggested_remediation = self.vulnerability.vendor_recommendation
        return self.suggested_remediation

    def display_report(self):
        print("=" * 50)
        print(f"Asset: {self.asset.hostname}")
        print(f"IP Address: {self.asset.ip_address}")
        print(f"Environment: {self.asset.environment}")
        print()
        print(f"CVE: {self.vulnerability.cve}")
        print(f"CVSS Base Score: {self.vulnerability.cvss_score}")
        print(f"Adjusted Risk Score: {self.adjusted_risk_score}")
        if self.adjusted_priority == "Critical":
            emoji = "🔴"
        elif self.adjusted_priority == "High":
            emoji = "🟠"
        elif self.adjusted_priority == "Medium":
            emoji = "🟡"
        else:
            emoji = "🟢"

        print(f"Priority: {emoji} {self.adjusted_priority}")
        print()
        print("Reasoning")
        print("-" * 9)
        for reason in self.generate_reasoning():
            print(f"• {reason}")
        print()
        print("Suggested Remediation")
        print("-" * 21)
        print(self.generate_suggested_remediation())
        print()
        print("=" * 50)