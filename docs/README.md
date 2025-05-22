# 2025SE-Crawf.L-PassManaging

[![Build Windows Executable](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/windows-build-app.yml/badge.svg)](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/windows-build-app.yml)
[![Build Linux Executable](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/linux-build-app.yml/badge.svg)](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/linux-build-app.yml)


Password manager for my major

## Building the Executable on Windows

1. Download the repository
2. Ensure that `bash` is installed via WSL2
   1. Install [Windows Subsytem for Linux 2](https://learn.microsoft.com/en-us/windows/wsl/install) or run the following command on PowerShell and follow the instructions from there:
      ``` powershell
      wsl --install
      ```

3. Install Python (3.13 or greater) from [python.org/downloads](https://www.python.org/downloads/).

4. Restart Windows. *Optional PowerShell command below*:
   ```
   shutdown /g /soft
   ```

5. Install the required dependencies in `bash`:
   ```bash
   # Pyinstaller is required
   pip install pyinstaller
   pip install -r requirements.txt
   ```
