# here I am building the fist google chrome plugin where since my device possibly has latest version of chrome there might be no vuls mapped # and I cannot find any related cveid's so I am considering the present version as vculnerable and adding the related cve id's and steps to # remediate trying to replicate the actual va report from org.

# Here I will be taking the output from main file and from for related outdate version of file necessary data like references, cve id's, 
# remediation steps and if possible the path of the file will be included.

# Google Chrome               147.0.7727.102   this is the chrome version in my device and I consider this vulnerable




# import json
# with open("sysinfo_report.json" ,"r") as output:

#     for app in output:
#       if app.get("name") == "Google Chrome":
#         print("Name:", app["name"])
#         print("Version:", app["version"])


import json

with open("./sysinfo_report.json", "r") as f:
    data = json.load(f)
# print(type(data))
for app in data["installed_apps"]:
    if app.get("name") == "Google Chrome" and app.get("version") == "147.0.7727.102":
        tester=app.get("version")
        print(tester)
        print(f"the version of google chrome {tester} is outdated and is vulnerable to cve 2023-5219 CVE-2023-5217 \n(Critical/High): A heap buffer overflow in vp8 encoding within the libvpx library. This allowed remote attackers to execute arbitrary code or cause crashes via a crafted HTML page. It was actively exploited in the wild.\n CVE-2023-5187 (High): Use after free in Extensions.CVE-2023-5186 (High): Use after free in Passwords. \nHong Kong Computer Emergency Response Team Coordination CentreHong Kong Computer Emergency Response Team Coordination Centre+3\nRisk and Mitigation:These vulnerabilities primarily allow remote code execution, elevation of privilege, and denial of service. The update was critical for Windows, Mac, and Linux users to prevent exploitation. If you are using this version or older, you should update immediately to the latest available version")
        
    elif app.get("name") == "Google Chrome" and app.get("version") == "148.0.7727.101":
        print(f"the version of google chrome {tester} is outdated and is vulnerable to cve 2023-5219 CVE-2023-5217 \n(Critical/High): A heap buffer overflow in vp8 encoding within the libvpx library. This allowed remote attackers to execute arbitrary code or cause crashes via a crafted HTML page. It was actively exploited in the wild.\n CVE-2023-5187 (High): Use after free in Extensions.CVE-2023-5186 (High): Use after free in Passwords. \nHong Kong Computer Emergency Response Team Coordination CentreHong Kong Computer Emergency Response Team Coordination Centre+3\nRisk and Mitigation:These vulnerabilities primarily allow remote code execution, elevation of privilege, and denial of service. The update was critical for Windows, Mac, and Linux users to prevent exploitation. If you are using this version or older, you should update immediately to the latest available version")
    
    
    elif app.get("name") == "Google Chrome" and app.get("version") == "148.0.7727.100":
        print(f"the version of google chrome {tester} is outdated and is vulnerable to cve 2023-5219 CVE-2023-5217 \n(Critical/High): A heap buffer overflow in vp8 encoding within the libvpx library. This allowed remote attackers to execute arbitrary code or cause crashes via a crafted HTML page. It was actively exploited in the wild.\n CVE-2023-5187 (High): Use after free in Extensions.CVE-2023-5186 (High): Use after free in Passwords. \nHong Kong Computer Emergency Response Team Coordination CentreHong Kong Computer Emergency Response Team Coordination Centre+3\nRisk and Mitigation:These vulnerabilities primarily allow remote code execution, elevation of privilege, and denial of service. The update was critical for Windows, Mac, and Linux users to prevent exploitation. If you are using this version or older, you should update immediately to the latest available version")

    elif app.get("name") == "Google Chrome" and app.get("version") == "148.0.7727.99":
        print(f"the version of google chrome {tester} is outdated and is vulnerable to cve 2023-5219 CVE-2023-5217 \n(Critical/High): A heap buffer overflow in vp8 encoding within the libvpx library. This allowed remote attackers to execute arbitrary code or cause crashes via a crafted HTML page. It was actively exploited in the wild.\n CVE-2023-5187 (High): Use after free in Extensions.CVE-2023-5186 (High): Use after free in Passwords. \nHong Kong Computer Emergency Response Team Coordination CentreHong Kong Computer Emergency Response Team Coordination Centre+3\nRisk and Mitigation:These vulnerabilities primarily allow remote code execution, elevation of privilege, and denial of service. The update was critical for Windows, Mac, and Linux users to prevent exploitation. If you are using this version or older, you should update immediately to the latest available version")
 