"""Analyst knowledge base: response guidance, questions to ask, travel hubs. Edit freely."""
HUBS = {"AE", "SA", "TR", "GB", "DE", "FR", "US", "QA", "KW", "IT"}

REC = {
    "R01": "Block the source IP at the WAF/edge; enable velocity limits on /v1/payments; notify issuing banks; review affected cards.",
    "R02": "Force sign-out and password + MFA reset; verify with the customer through a known channel; review transactions after the foreign login.",
    "R03": "Block attacking IPs; enforce rate limiting/CAPTCHA; force reset for accounts that logged in successfully; check credential reuse.",
    "R04": "Freeze the wallet; recall the payout if possible; contact the customer; verify SIM swap with the carrier; open a fraud case.",
    "R05": "Rotate the merchant API key; confirm activity with the merchant; add an IP/country allow-list for the key.",
    "R06": "Confirm with the administrator; kill the VPN session if unexpected; review actions taken during the session.",
    "R07": "Suspend the user's KYC access pending review; preserve access logs; assess personal-data exposure and PDPL notification duty.",
    "R08": "Rotate the service-account credentials; capture query logs; determine what data left; engage DBA and incident lead.",
    "R09": "Revert the webhook to the registered URL; contact the merchant; review refunds issued after the change.",
    "R10": "Block further MFA prompts; reset credentials; enable number matching; educate the user about push fatigue.",
    "R11": "Block the IP/ASN; add bot protection to the mobile gateway; review API rate limits.",
    "R12": "Verify the role grant with its approver; revoke if unauthorized; review actions of the new administrator.",
    "R13": "Hold the payout; contact the account owner and verify identity; review dormant-account policy.",
    "R14": "Review the login; require step-up authentication; consider blocking TOR exits for sensitive actions.",
    "R15": "Isolate the host; collect memory and process tree; hunt fleet-wide for the binary; start the incident response procedure.",
}
DEFAULT_REC = "Follow the standard incident response procedure and document findings."

QUESTIONS = {
    "R01": ["Did the issuing banks report a spike in declined authorisations for these cards?", "Is the source IP a known payment-gateway partner?"],
    "R02": ["Did the customer confirm the foreign login (call-back on a registered number)?", "Is there a travel notice or a known roaming SIM for this customer?"],
    "R03": ["Did any of the targeted accounts log in successfully from this IP afterwards?", "Is the IP part of a known credential-stuffing infrastructure list?"],
    "R04": ["Did the carrier confirm a SIM replacement request for this number?", "Was the payout destination ever used by this customer before?"],
    "R05": ["Did the merchant open a new branch/server in this country?", "Does the user-agent match the merchant's usual SDK?"],
    "R06": ["Is there an approved change or on-call ticket for this administrator?", "Does the source IP match the administrator's usual connection?"],
    "R07": ["Is there a support case or audit task that justifies reading this many KYC records?", "Were records exported or only viewed?"],
    "R08": ["Was a scheduled report/ETL job released today?", "Which tables were read and do they contain personal data?"],
    "R09": ["Did the merchant request this webhook change through the registered channel?", "Were refunds issued after the change?"],
    "R10": ["Did the customer approve any of the prompts?", "Is the prompt volume coming from the customer's own device?"],
    "R11": ["Is this a monitoring/uptime partner on the allow-list?", "Do requests enumerate customer identifiers?"],
    "R12": ["Who approved this role grant and in which ticket?", "Why was the grant performed by a service account?"],
    "R13": ["Did the account owner confirm the payout?", "Was the contact information changed recently?"],
    "R14": ["Does the customer normally use privacy tools/VPN?", "Was a sensitive action performed after the login?"],
    "R15": ["Is the binary part of an approved admin toolkit or pentest?", "Which user and parent process launched it?"],
}
