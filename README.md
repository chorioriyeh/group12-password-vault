# Password Vault

A secure local password manager with encryption, built for virtual environment deployment.

## Features
- Master password protection
- Fernet (AES-256) encryption for stored passwords
- Password generation
- Clipboard integration
- SQLite database storage
- Change master password functionality
- Graphical User interface

##Screenshots of the Password Vault
- <img width="315" height="153" alt="Screenshot (111 2)" src="https://github.com/user-attachments/assets/52389529-b896-4f1c-824e-696c95363b2e" />
- <img width="312" height="332" alt="Screenshot (112 2)" src="https://github.com/user-attachments/assets/c23a3d9f-cefa-4858-870e-1718f031abc6" />

## The Link for the Demo Video
https://drive.google.com/file/d/1elySDSygwIwpXa8Py7FZ_xUtSqHvPN6t/view?usp=sharing


## Installation with Virtual Environment

1. Create and activate virtual environment:
```bash                                                                                                                                                                                    python -m venv venv                                                                                                                                                                        On Mac: source venv/bin/activate                                                                                                                                                           On Windows: venv\Scripts\activate                                                                                                                                                          ```
2. Install the dependencies:                                                                                                                                                             Any dependencies that you make be lacking can be installed on the terminal by writing this code --- pip install dependency-name
```bash
pip install pipenv
pipenv install
```

3. Running with the Virtual Environment
```bash
pipenv shell
python -m gui_vault
```
        OR
Right click the gui_vault.py file, Then Select run python file on the terminal




