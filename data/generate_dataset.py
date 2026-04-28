

import pandas as pd
import random
import re

random.seed(42)

PHISHING_EMAILS = [
    {"subject": "URGENT: Your account has been suspended", "sender": "security@bankofamerica-verify.net",
     "body": "Dear Customer, We have detected UNUSUAL ACTIVITY on your account. Your account has been TEMPORARILY SUSPENDED. You must verify your identity IMMEDIATELY or your account will be permanently closed within 24 hours. Click here: http://bankofamerica-secure-login.xyz/verify. Provide your Social Security Number and account password for verification. This is your FINAL WARNING.", "label": 1, "attack_type": "credential_harvest"},
    {"subject": "PayPal: Action Required - Verify Your Account", "sender": "noreply@paypal-secure-update.com",
     "body": "Your PayPal account has been limited. To restore full access, please verify your information immediately. Failure to do so within 48 hours will result in permanent account suspension. Click here to verify: http://paypal-account-verify.ru/login. Enter your email, password, and credit card details.", "label": 1, "attack_type": "credential_harvest"},
    {"subject": "Urgent wire transfer needed - confidential", "sender": "ceo.smith@company-corp.net",
     "body": "Hi, I need you to process a wire transfer urgently. I am in a board meeting and cannot talk. Amount: $47,500 to Shenzhen Trade Partners. Account: 8827364910. This must be done before 3pm today for a confidential acquisition. Do not discuss with anyone in the office. Confirm when done. Thanks, Robert Smith CEO", "label": 1, "attack_type": "bec"},
    {"subject": "Confidential - Gift cards needed ASAP", "sender": "director@acme-corp.info",
     "body": "I need you to purchase 10 Google Play gift cards worth $100 each for a client surprise. Buy them now and send me the codes. Keep this between us - it is a surprise. I will reimburse you. This is urgent. Do not call me, I am in meetings all day.", "label": 1, "attack_type": "bec"},
    {"subject": "Password Expiry Notice - Reset Required", "sender": "IT-Support@company-helpdesk.co",
     "body": "Your VPN password expires in 2 hours. Reset now at http://reset.company-helpdesk.co/vpn to avoid losing access. Enter your current username and password first to verify your identity. If not reset, your account will be locked for 3-5 business days.", "label": 1, "attack_type": "it_impersonation"},
    {"subject": "Microsoft 365: Your account will be disabled", "sender": "admin@microsoft-365-support.net",
     "body": "Your Microsoft 365 account will be disabled in 24 hours due to a security policy update. Login at http://microsoft365-secure.xyz/update to prevent disruption. You will need to re-enter your credentials and update your payment information.", "label": 1, "attack_type": "it_impersonation"},
    {"subject": "Invoice #8472 - Payment Required", "sender": "billing@invoices-corp.net",
     "body": "Please find attached Invoice #8472 for $12,400 for services in November. Due within 5 days. Open the attached Invoice_8472.xlsm and enable macros to view full details. Contact billing@invoices-corp.net with questions.", "label": 1, "attack_type": "malware_delivery"},
    {"subject": "Your package could not be delivered", "sender": "delivery@fedex-tracking-update.com",
     "body": "We attempted to deliver your package but were unable to. To reschedule delivery, download and open the attached form (DeliveryForm.doc) and enable editing. Your package will be returned after 3 days. Tracking: FX-28374923.", "label": 1, "attack_type": "malware_delivery"},
    {"subject": "Congratulations! You have won $1,500,000", "sender": "lottery@uk-national-lottery.win",
     "body": "Dear Winner, Your email has been selected in our annual lottery. You have won $1,500,000 USD. To claim your prize, send your full name, address, bank account details, and a processing fee of $250 to lottery@uk-national-lottery.win. Respond within 72 hours or forfeit your prize.", "label": 1, "attack_type": "advance_fee"},
    {"subject": "Shared document - Q4 Budget Review", "sender": "drive-noreply@google-docs-share.com",
     "body": "John Smith has shared a document with you: Q4 Budget Review.pdf. Click to view: http://googledocs-viewer.xyz/doc?id=8472. You may need to sign in with your Google credentials to access this document.", "label": 1, "attack_type": "spear_phish"},
    {"subject": "LinkedIn: You have 3 new connection requests", "sender": "connections@linkedin-notifications.net",
     "body": "You have 3 pending connection requests. View and accept at http://linkedin-secure.co/connections. Log in with your LinkedIn email and password. Offers expiring soon from recruiters at top companies.", "label": 1, "attack_type": "spear_phish"},
    {"subject": "Following up on our call - account verification", "sender": "support@amazon-account-security.com",
     "body": "Following our phone call, please complete your account verification at http://amazon-secure-verify.net. You will need your account password, credit card number, and billing address. This must be completed within 12 hours to restore your account.", "label": 1, "attack_type": "credential_harvest"},
    {"subject": "Your Facebook account will be deleted", "sender": "security@facebook-account-support.com",
     "body": "Your Facebook account has been reported for violating community guidelines. To appeal this decision and prevent permanent deletion, verify your account at http://facebook-verify.ru/appeal within 24 hours. Provide your login email and password.", "label": 1, "attack_type": "credential_harvest"},
    {"subject": "IRS: Tax Refund Pending - Claim Now", "sender": "refunds@irs-gov-refunds.com",
     "body": "The Internal Revenue Service has a tax refund of $3,200 pending for you. To claim your refund, provide your Social Security Number, date of birth, bank account and routing number at http://irs-refund-claim.net. Unclaimed refunds expire after 30 days.", "label": 1, "attack_type": "credential_harvest"},
    {"subject": "FINAL NOTICE: Debt Collection", "sender": "legal@debt-collection-agency.biz",
     "body": "This is your FINAL NOTICE regarding an outstanding debt of $4,891. Legal action will be taken within 48 hours unless payment is made immediately. Click here to pay: http://debtpay-now.xyz. Provide your credit card or bank account details. Ignoring this notice may result in wage garnishment.", "label": 1, "attack_type": "advance_fee"},
]

LEGITIMATE_EMAILS = [
    {"subject": "What's new in Notion - December Update", "sender": "newsletter@notion.so",
     "body": "Hi there, We have shipped some exciting updates this month. New features include AI writing assistant improvements, better database formulas, and calendar view updates. Read the full changelog at https://www.notion.so/releases. Happy building! The Notion Team. Unsubscribe | Privacy Policy", "label": 0, "attack_type": "none"},
    {"subject": "Your GitHub pull request was merged", "sender": "noreply@github.com",
     "body": "Your pull request feature/user-authentication was merged into main by johndoe. View the merge at https://github.com/org/repo/pull/142. You can unsubscribe from these emails in your notification settings.", "label": 0, "attack_type": "none"},
    {"subject": "Q3 Sales Report - Team Review", "sender": "sarah.johnson@company.com",
     "body": "Hi team, Please find the Q3 sales report attached for tomorrow's review meeting. Key highlights: revenue up 12% QoQ, new customer acquisition exceeded targets by 8%. Let me know if you have any questions before the meeting at 2pm. Best, Sarah", "label": 0, "attack_type": "none"},
    {"subject": "Your Amazon order has shipped", "sender": "shipment-tracking@amazon.com",
     "body": "Your order #112-8473621-9284736 has shipped. Estimated delivery: Thursday, December 14. Track your package at https://www.amazon.com/gp/your-account/ship-track. Items: USB-C Hub x1. Thank you for shopping with Amazon.", "label": 0, "attack_type": "none"},
    {"subject": "Meeting invite: Weekly team standup", "sender": "calendar@google.com",
     "body": "You have been invited to Weekly Team Standup, every Monday at 10am. Organizer: mike@company.com. Join at https://meet.google.com/abc-defg-hij. This is a recurring event. You can accept or decline this invitation in Google Calendar.", "label": 0, "attack_type": "none"},
    {"subject": "Slack: 5 new messages in #engineering", "sender": "feedback@slack.com",
     "body": "You have 5 unread messages in #engineering. Recent activity from your team. Open Slack at https://app.slack.com or in your desktop app to catch up. Update your notification preferences at https://slack.com/account/notifications.", "label": 0, "attack_type": "none"},
    {"subject": "Your Spotify Premium receipt", "sender": "no-reply@spotify.com",
     "body": "Thanks for your payment. Spotify Premium Individual plan: $9.99 for December 2024. Your subscription renews on January 14, 2025. View your account at https://www.spotify.com/account. Questions? Visit https://support.spotify.com.", "label": 0, "attack_type": "none"},
    {"subject": "Jira: Issue PROJ-2847 assigned to you", "sender": "jira@atlassian.net",
     "body": "Alice has assigned you an issue in PROJ: [PROJ-2847] Fix login redirect bug. Priority: High. Due: December 20. View and comment at https://yourorg.atlassian.net/browse/PROJ-2847. You can manage your notification preferences in Jira settings.", "label": 0, "attack_type": "none"},
    {"subject": "Your flight confirmation - DEL to BLR", "sender": "noreply@indigoair.in",
     "body": "Booking confirmed! Flight 6E-204, Delhi to Bangalore, December 18 at 07:15. PNR: XYZ123. Check in online at https://www.goindigo.in/check-in.html 48 hours before departure. Web check-in opens December 16.", "label": 0, "attack_type": "none"},
    {"subject": "LinkedIn: John viewed your profile", "sender": "messages-noreply@linkedin.com",
     "body": "John Smith, Senior Engineer at Google, viewed your profile. See who has viewed your profile at https://www.linkedin.com/me/profile-views/. You are receiving this email because you have LinkedIn account notifications enabled.", "label": 0, "attack_type": "none"},
    {"subject": "Course update: New lecture added", "sender": "no-reply@coursera.org",
     "body": "A new lecture has been added to Machine Learning Specialization: Advanced Neural Networks. Continue your course at https://www.coursera.org/learn/machine-learning. You are 68% through the course. Keep up the great work!", "label": 0, "attack_type": "none"},
    {"subject": "Project update: documentation complete", "sender": "teammate@vit.ac.in",
     "body": "Hi team, I have finished the Computer Networks project documentation. All sections are complete including the network topology, protocol stack, and security analysis. Please review the shared document and let me know your feedback by Friday. Thanks", "label": 0, "attack_type": "none"},
    {"subject": "Stack Overflow: Answer accepted on your question", "sender": "noreply@stackoverflow.com",
     "body": "Your answer to How to use SHAP with XGBoost was accepted by the asker. You earned 15 reputation points. View the question at https://stackoverflow.com/questions/12345678. Thanks for contributing to Stack Overflow!", "label": 0, "attack_type": "none"},
    {"subject": "Monthly bank statement available", "sender": "alerts@hdfcbank.com",
     "body": "Your HDFC Bank account statement for November 2024 is now available. Login to NetBanking at https://www.hdfcbank.com/netbanking to view or download your statement. For security, never share your NetBanking credentials with anyone.", "label": 0, "attack_type": "none"},
    {"subject": "Zoom: Recording available - Team Meeting Dec 10", "sender": "no-reply@zoom.us",
     "body": "Your cloud recording from Team Meeting on December 10, 2024 is now available. View the recording at https://zoom.us/rec/share/abc123. The recording will be available for 30 days. Manage your recordings at https://zoom.us/recording.", "label": 0, "attack_type": "none"},
]

def augment_emails(emails, n_augmented=10):
    augmented = []
    urgency_vars = ["immediately", "right now", "as soon as possible", "without delay", "now"]
    for email in emails[:n_augmented]:
        new = email.copy()
        body = new["body"]
        for u in urgency_vars:
            if u in body.lower():
                replacement = random.choice([v for v in urgency_vars if v != u])
                body = re.sub(u, replacement, body, flags=re.IGNORECASE, count=1)
                break
        new["body"] = body
        new["subject"] = new["subject"] + " " + random.choice(["- Urgent", "- Action Required", "- Important"])
        augmented.append(new)
    return augmented

def build_dataset():
    all_emails = []
    all_emails.extend(PHISHING_EMAILS)
    all_emails.extend(LEGITIMATE_EMAILS)
    augmented = augment_emails(PHISHING_EMAILS, n_augmented=len(PHISHING_EMAILS))
    all_emails.extend(augmented)
    for email in LEGITIMATE_EMAILS[:8]:
        new = email.copy()
        new["subject"] = new["subject"] + " (follow-up)"
        new["body"] = "Following up on our previous message. " + new["body"]
        all_emails.append(new)
    df = pd.DataFrame(all_emails)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Dataset built: {len(df)} samples")
    print(f"  Phishing: {df['label'].sum()} ({df['label'].mean()*100:.1f}%)")
    print(f"  Legitimate: {(df['label']==0).sum()} ({(df['label']==0).mean()*100:.1f}%)")
    print(f"  Attack types: {df['attack_type'].value_counts().to_dict()}")
    return df

if __name__ == "__main__":
    df = build_dataset()
    print(df.head())
