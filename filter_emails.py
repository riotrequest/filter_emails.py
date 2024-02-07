import subprocess
import re

# Define the date, IP address, and the range of hours you want to check
date = "03/02/2024"
ip_address = "YOUR_IP_ADDRESS"
start_hour = 4
end_hour = 6
output_file = "email_addresses.csv"

# Open the file for writing
with open(output_file, "w") as file:
    # Loop through each hour and minute from start_hour to end_hour
    for hour in range(start_hour, end_hour + 1):
        for minute in range(60):
            timestamp = f"{date} {hour:02d}:{minute:02d}"
            command = f"/var/hvmail/bin/hvmail_get_possible_spamtrap_hits --dd-mm-yyyy-timestamp \"{timestamp}\" {ip_address}"
            
            # Run the command
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # Use regular expression to find email addresses in the command output
            emails = re.findall(r'email=<([^>]+)>', stdout.decode('utf-8'))
            
            # Print the found email addresses and write them to the file
            for email in emails:
                print(email)
                file.write(email + "\n")
