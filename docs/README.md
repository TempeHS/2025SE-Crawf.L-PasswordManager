# 2025SE-Crawf.L-PassManaging

[![Build Windows Executable](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/windows-build-app.yml/badge.svg)](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/windows-build-app.yml)
[![Build Linux Executable](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/linux-build-app.yml/badge.svg)](https://github.com/TempeHS/2025SE-Crawf.L-PassManaging/actions/workflows/linux-build-app.yml)


Password manager for my major

## Building the Executable on Windows

1. Ensure that `bash` is installed.
   
   1. If not, see instructions to install `bash` for [Windows 11](https://www.google.com.au/search?q=how+to+install+bash+windows+11&num=20&newwindow=1&udm=14) or [Windows 10](https://www.google.com.au/search?q=how+to+install+bash+windows+10&num=20&newwindow=1&udm=14) (not recommended to run on Windows 10). *See individual instructions for your Linux distro.*

2. Install Python (3.13 or greater) from [python.org/downloads](https://www.python.org/downloads/).

3. Install the required dependencies in `bash` only:
   ``` bash
   # Pyinstaller is required
   pip install pyinstaller
   pip install -r requirements.txt
   ```
