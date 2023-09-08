# Murari
---
## Murari is a command-line tool built using Python that empowers cybersecurity professionals to enhance email security and conduct thorough email analysis.

### Features of Murari:

- Email Header Analysis: Murari provides a streamlined approach to email header analysis, extracting metadata such as sender information, email authentication protocol details, IP details and more.
- Efficient Attachment and Link Analysis: Murari equips users with the ability to perform analysis of email attachments and URLs, mitigating potential risks. Using Python libraries and external APIs, this command line tool scans attachments for malicious indicators. By detecting risky links, it helps prevent users from falling victim to phishing attacks.
- VirusTotal Integration: Murari seamlessly integrates with the VirusTotal API, enabling users to check hash and URL reputations against multiple antivirus engines and threat intelligence sources. This integration provides real-time insights into the safety and reputation of email content.

### This project is useful for:

- Cyber Forensic
- Threat Hunting
- SOC, Threat or Malware Analysts
- Cybersecurity Awareness Programs

## Installation:

**Note**: Python-3 must be installed and ViruTotal api key must be pasted before running this script.
```
api_key = "<Enter your VirusTotal API"
```

1. Clone the Murari repository to your local machine
```
  git clone https://github.com/asimtarapathak/Murari.git
```
2. Extract the file and Navigate to the Murari directory:
```
  cd Murari
```
3. Run cmd and Install the required dependencies using pip:
```
  pip install -r requirements.py
```

