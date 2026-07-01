import os
import requests
import time

base_files_url = "https://www.virustotal.com/api/v3/files"
base_analyses_url = "https://www.virustotal.com/api/v3/analyses"
headers = {"accept": "application/json", "x-apikey": "210fb61ebfce43bf6d12b3ec2b63fd18db09712972416ca69619b86c5c404546"}

malicious_count = 0
suspicious_count = 0
clear_count = 0

def post(post_url, file_path, file_name):
    files = {"file": (file_name, open(file_path, "rb")) }
    response = requests.post(post_url, files=files, headers=headers)
    return response

def get(get_url):
    response = requests.get(get_url, headers=headers)
    return response


def final_print(file_name, file_data):
    global malicious_count, suspicious_count, clear_count
    stats = file_data["data"]["attributes"]["stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    if malicious > 0:
        print(f"{file_name} is flagged as malicious by {malicious} engine/s")
        malicious_count += 1
    elif suspicious > 0:
        print(f"{file_name} is flagged as suspicious by {suspicious} engine/s")
        suspicious_count += 1
    else:
        print(f"{file_name} is clear")
        clear_count += 1



def scan(file_path, file_name):
    response = post(base_files_url, file_path, file_name)
    status_code = response.status_code
    if status_code == 200:
        post_data = response.json()

        id = post_data["data"]["id"]
        get_url = f"{base_analyses_url}/{id}"
        print(f"waiting for {file_name} to be checked by VirusTotal")
        while True:
            file_data = get(get_url).json()
            status = file_data["data"]["attributes"]["status"]
            if status == "completed":
                final_print(file_name, file_data)
                break
            elif status == "queued" or status == "in-progress":
                print(f"{status} checking again in 5 seconds")
                time.sleep(5)
            else:
                print(f"{file_name} - status error: status {status}")
    else:
        print(f"{file_name} - status code error: code {status_code}")
    
file_count = 0

def go_over_path(path):
    global file_count
    name_list = os.listdir(path)
    for name in name_list:
        cur_full_path = os.path.join(path, name)
        
        if os.path.isfile(cur_full_path):
            file_count += 1
            scan(os.path.relpath(cur_full_path, os.getcwd()), name)
        
        else:
            go_over_path(cur_full_path)

path = input("Enter path:\n")

go_over_path(path)

print(f"SUMMERY: amount of files {file_count}, from them {malicious_count} are malicious, {suspicious_count} are suspicious and {clear_count} are clear")