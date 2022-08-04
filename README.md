# Fuzzing-Detector
![d64c474d15cfc591e60c809ad7826101](https://user-images.githubusercontent.com/93203695/182835786-980d43cc-66d4-43ab-a7e5-8e95c56f2931.jpg)

## Detecting Fuzzing Attacks
### About The Project
This script detects fuzzing attacks on SSH protocol.
A fuzzing attack is an automated process used to find application vulnerabilities.
It consists of inserting massive amounts of random data, or fuzz, into source code and observing the outcomes.
A successful fuzzing attack brings areas prone to malicious cyber intrusion, code insertion,
and data retrieval to light, putting applications in danger of a serious application attack.
With this script we would like to avoid this attack.
* The Secure Shell (SSH) is a protocol for secure remote login and
    other secure network services over an insecure network.
    The SSH transport layer is a secure, low level transport protocol.
- Information about SSH protocol is taken from:
https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
- Informarion about Fuzzing is taken from:
https://www.contrastsecurity.com/knowledge-hub/glossary/fuzzing
- This script is detecting fuzzing attacks on your machine by inspecting log files.
- after inspecting logs on a Kali Linux machine, I identified that the date format of the logs is: 
%b %d %H:%M:%S
- %b - The first 3 letters of the month, the first is uppercase.
- %d - Numeric day.
- %H:%M:%S - 00:00:00 Hours:Minutes:Seconds
If the date is written differently on the machine you are running the script on, 
note that you should change the date format so it will compile and run. 
__PLEASE NOTE THAT__ my whole program depends on correctly reading from log files. 
### Usage
- Download the script to your linux machine. I developed it on Ubuntu so it's the preffered machine for this script.
- Run it.
- On a Kali linux machine, use Metasploit to attack your machine with a fuzzing attack.
- Example for attack: https://www.infosecmatter.com/metasploit-module-library/?mm=auxiliary/fuzzers/ssh/ssh_version_2
<img width="534" alt="fuzzingDetected" src="https://user-images.githubusercontent.com/93203695/182831415-bec5d834-15f9-42c3-a20a-12209a54f6b2.png">
