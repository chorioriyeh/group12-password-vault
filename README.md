# Password Vault

A secure local password manager with encryption, built for virtual environment deployment.

## Features
- Master password protection
- AES-256 encryption for stored passwords
- Password generation
- Clipboard integration
- SQLite database storage
- Change master password functionality
- Graphical User interface

## Installation with Virtual Environment

1. Create and activate virtual environment:
```bash
python -m venv venv
On Mac: source venv/bin/activate
On Windows: venv\Scripts\activate

2. Install the dependencies
### Any dependencies that you make be lacking can be installed on the terminal by writing this code --- pip install dependency-name
```bash
pip install pipenv
pipenv install

3. Running with the Virtual Environment
```bash
pipenv shell
python gui_vault.py
        OR
Right click the gui_vault.py file, Then Select run on the integrated terminal
