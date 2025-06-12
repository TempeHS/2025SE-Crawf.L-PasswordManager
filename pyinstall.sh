#!/bin/bash
# Make sure to run this script from the root directory of the project

clear

# Install all dependencies
pip install -r requirements.txt --upgrade

# clear all files in 'dist/' directory
rm ./dist/*


pyinstaller --add-data "help.txt;." main.py


# Remove the ./dist/main directory if it exists
if [ -d "./dist/main" ]; then
	rm -rf ./dist/main
fi

# Create a executable (for testing purposes)
pyinstaller --clean --noconfirm --debug all --noconsole main.py


# Copy the help file into the '_internal' directory as 'help.txt'
cp ./pyinstall_help.txt ./dist/main/_internal/help.txt
