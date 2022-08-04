"""
SSH Fuzzing Attack Detection Script.
By : Dana Zorohov
This script detects fuzzing attacks on SSH(*) protocol.
A fuzzing attack is an automated process used to find application vulnerabilities.
It consists of inserting massive amounts of random data, or fuzz, into source code and observing the outcomes.
A successful fuzzing attack brings areas prone to malicious cyber intrusion, code insertion,
and data retrieval to light, putting applications in danger of a serious application attack.
With this script we would like to avoid this attack.

(*) The Secure Shell (SSH) is a protocol for secure remote login and
    other secure network services over an insecure network.
    The SSH transport layer is a secure, low level transport protocol.

Information about SSH protocol is taken from:
https://datatracker.ietf.org/doc/html/rfc4253#section-4.2

Informarion about Fuzzing is taken from:
https://www.contrastsecurity.com/knowledge-hub/glossary/fuzzing

"""
# for time stamps
import time
from datetime import datetime

# regex (needed for the time expressions)
import re

# will use as global vars to use as counters:

msg1 = 0

msg2 = 0

msg3 = 0

msg4 = 0

msg5 = 0

"""
This function is checking the logs to find 
alerts that occurs when the machine is under a fuzzing attack.
"""


def logs_reader():

    # taking the time now for the sample
    time_now = datetime.now()

    # convert date, time to its equivalent string
    time_now_str = time_now.strftime("%b %d %H:%M:%S")

    # combine a regular expression pattern into pattern object time
    regex_time = re.compile(r'([ADFJMNOS]\w* [\d]{1,2} \d+:\d+:\d+)')

    time_now_str = time.strptime(time_now_str, "%b %d %H:%M:%S")

    # opening the file with the logs to check and searching for the strings that points on ssh fuzzing attack
    # we only need to read the file so we'll open it with read mode
    with open("/var/log/auth.log", "r") as SF:

        # looping over all the lines in the sample file
        for line in SF.readlines():

            # The re.search() method takes a regular expression pattern and a string and
            # searches for that pattern within the string.
            # so we are searching for the line at the exact time we defined above.
            # If the search is successful, search() returns a match object or None otherwise.
            at_time_line = regex_time.search(line)

            # when we find a line at this time:
            if at_time_line:
                time_to_check = at_time_line.group()
                time_to_check = time.strptime(time_to_check, "%b %d %H:%M:%S")

                # if the time is after or at the same time we defined
                if time_to_check >= time_now_str:

                    # sending to helper function that checks if the line contains
                    # the message that occurs when ssh fuzzing attack happens
                    # strip() - Remove spaces at the beginning and at the end of the string
                    msg_kex_counter(at_time_line.string.strip())
                    if msg1 > 5 or msg2 > 5 or msg3 > 5 or msg4 > 5 or msg5 > 10:
                        print("Fuzzing detected")
                        exit()


"""
This function checks how many times the messages that happens when
the machine is under ssh fuzzing attack are there.
After inspecting logs while ssh fuzzing attack,
I found out that the messages that appears the most and detect that fuzzing occurred are: 
- kex_exchange_identification : The error refers to the fact that a connection was first established
  but then interrupted for some reason. 
  some of those reasons are:
  - The socket connection between the SSH server and the client has been interrupted.
  - The SSH daemon could be consuming an unreasonably large amount of network resources.
- kex_input_kexinit : a function of the component Key Exchange Initialization.  
  manipulation with an unknown input leads to a denial of service vulnerability.
- Connection closed by : Sometimes while connecting to SSH servers, users often encounter
  “Connection refused” error by port 22. It happens because of several reasons like SSH service is not running,
  the port is blocked by the firewall, or the server is using a different port.
  It can also occur because of the IP conflict issue. 
- Bad protocol version : This is octal representation (base 8). During the initial steps of a SSH connection,
  the client and the server send each other the version(s) of the protocol they implement, as strings.
  These strings must follow a specific format. 
- "Connection closed by "
   
"""


def msg_kex_counter(line: str):

    # using global vars to count occurrences of any of these messages

    # The find() method finds the first occurrence of the specified value.
    # The find() method returns -1 if the value is not found.

    # message number 1 we check
    # when the message "kex_exchange_identification" appears in the sampled line:
    if line.find("kex_exchange_identification") != -1:
        global msg1
        msg1 += 1

    # message number 2 we check
    # when the message "kex_input_kexinit" appears in the sampled line:
    elif line.find("kex_input_kexinit") != -1:
        global msg2
        msg2 += 1

    # message number 3 we check
    # when the message "Bad protocol version" appears in the sampled line:
    elif line.find("Bad protocol version") != -1:
        global msg3
        msg3 += 1

    # message number 4 we check
    # when the message "send_error: write: Broken pipe" appears in the sampled line:
    elif line.find("send_error: write: Broken pipe") != -1:
        global msg4
        msg4 += 1

    # message number 5 we check
    # when the message "Connection closed by " appears in the sampled line:
    elif line.find("Connection closed by ") != -1:
        global msg5
        msg5 += 1


if __name__ == '__main__':
    while True:
        logs_reader()