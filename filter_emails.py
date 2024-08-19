import subprocess
import re

# Prompt the user for inputs
date = input("Enter the date (dd/mm/yyyy): ")
ip_address = input("Enter the IP address: ")
start_hour = int(input("Enter the start hour (0-23): "))
end_hour = int(input("Enter the end hour (0-23): "))
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

            if stderr:
                print(f"Error: {stderr.decode('utf-8')}")
                continue

            # Use regular expression to find email addresses in the command output
            emails = re.findall(r'email=<([^>]+)>', stdout.decode('utf-8'))
            
            # Print the found email addresses and write them to the file
            for email in emails:
                print(email)
                file.write(email + "\n")

print(f"Finished! The results are saved in {output_file}")
