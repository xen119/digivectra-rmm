import subprocess
import sys

SERVICE_NAME = "Spooler"

def restart():
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"Restart-Service -Name {SERVICE_NAME} -Force"],
            check=True,
            text=True,
        )
        print(f"Service {SERVICE_NAME} restarted successfully.")
    except subprocess.CalledProcessError as error:
        print(f"Failed to restart {SERVICE_NAME}: {error}", file=sys.stderr)


if __name__ == "__main__":
    restart()
