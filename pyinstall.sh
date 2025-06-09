#!/bin/bash
# Make sure to run this script from the root directory of the project

clear

# Install all dependencies
pip install -r requirements.txt --upgrade

# clear all files in 'dist/' directory
rm ./dist/*

# Create a executable (for testing purposes)
pyinstaller --clean --noconfirm --onefile --debug all --console --optimize 2 main.py

# Sample file to be copied to the 'dist/' directory
cp ./pyinstall_help.txt ./dist/help.txt