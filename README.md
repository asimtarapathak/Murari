# Murari
![Murari](https://github.com/asimtarapathak/Murari/assets/50657538/96c96635-de72-4891-b407-47e2495368a8)
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
api_key = "<Enter your VirusTotal API key>"
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


## Usage:

Murari provides two command line options to analyze email headers, attachments and links. Here are some examples:

1. For email header file analysing need to give email header file as parameter (.eml file)
```
 python main.py -f <email header file>
![SS1 1](https://github.com/asimtarapathak/Murari/assets/50657538/8d0bf5e4-f377-4ad8-8e0b-629a01783ad9)
![SS1 2](https://github.com/asimtarapathak/Murari/assets/50657538/2f18e5f6-fbd0-4f1a-879a-3b434065db28)
```

2. For analysing email attachments and links need to give email message file as parameter (.msg file)
```
  python main.py -o <outlook message file>
![SS2](https://github.com/asimtarapathak/Murari/assets/50657538/8403e6c5-9962-411a-8366-49a8a10ef3ed)
```

3. For a complete list of options and their descriptions, run:
```
  python main.py -h
![SS3](https://github.com/asimtarapathak/Murari/assets/50657538/018b2308-a46d-4cf2-afc3-73212cfcc6b4)
```

Thank you for choosing Murari! We hope this tool helps you effectively analyze email headers, attachments, and links and enhancing your email security. If you have any questions or need assistance, please don't hesitate to reach out.

Happy analyzing!
