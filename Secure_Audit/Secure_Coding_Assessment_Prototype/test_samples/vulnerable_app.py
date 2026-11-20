import os

username = input("Username: ")
filename = input("File: ")
password = input("Password: ")

os.system("ping " + username)

with open(filename, "r") as f:
    data = f.read()

try:
    process(data)
except:
    pass

temp_file = "/tmp/report.txt"
