# Backup Linux | main.py
#### Author: Bocaletto Luca

Interactive, single-file incremental backup tool with encryption, checksums, retention and restore—all in your terminal.

#### Language: 
English, Italian.

---

## Table of Contents

1. [Overview](#overview)  
2. [Features](#features)  
3. [Prerequisites](#prerequisites)  
4. [Installation](#installation)  
5. [Configuration](#configuration)  
6. [Usage](#usage)  
   - [Run Backup](#run-backup)  
   - [Restore Archive](#restore-archive)  
7. [Exclude Patterns](#exclude-patterns)  
8. [Logging](#logging)  
9. [Email Notifications](#email-notifications)  
10. [.backupignore Support](#backupignore-support)  
11. [Contributing](#contributing)  
12. [License](#license)  
13. [Author](#author)  

---

## Overview

`backup_main.py` is an all-in-one, interactive CLI utility for Linux (Debian/Ubuntu). It provides:

- Incremental backups based on file modification times  
- Compressed archives (`.tar.gz`) or parallel compression with `pigz`  
- GPG encryption of archives  
- SHA256 checksums for integrity verification  
- Automatic retention (rotation) of old backups  
- Interactive restore of encrypted backups  
- Persistent configuration stored in `~/.config/backup_main/config.json`  
- Exclude patterns and `.backupignore` support  
- Console and rotating file logging  
- Optional email notifications on success or failure  

Everything runs from a simple menu—no separate modules, just one file!

---

## Features

- **Interactive Menu**: Configure, run backup and restore without memorizing flags  
- **Persistent Config**: Your settings saved in `~/.config/backup_main/config.json`  
- **Incremental Snapshots**: Only changed or new files are archived  
- **Compression Options**: Native `tar.gz` or faster `pigz` if installed  
- **GPG Encryption**: Secure archives with your GPG key  
- **Checksums**: SHA256 record saved alongside each `.gpg` file  
- **Retention**: Automatically delete backups older than configured days  
- **Restore**: List and decrypt any backup to a target folder  
- **Exclude Patterns**: Filter out files or directories by glob pattern  
- **.backupignore**: Place patterns in source dir for project-specific ignores  
- **Logging**: Combines console output with daily rotating log files  
- **Email Alerts**: SMTP notifications for success or failure  

---

## Prerequisites

- Python 3.8+  
- GPG (`gnupg`) command-line tool  
- (Optional) `pigz` for parallel compression  
- An existing GPG key pair (public key on the machine for encryption)  
- SMTP server credentials if you want email notifications  

---

## Installation

1. Clone the repo  
   ```bash
   git clone https://github.com/bocaletto-luca/backup_main.py.git
   cd backup_main.py
   ```  
2. Install the Python dependency  
   ```bash
   pip install python-gnupg
   ```  
3. Make the script executable  
   ```bash
   chmod +x backup_main.py
   ```  

---

## Configuration

1. Launch the script  
   ```bash
   ./backup_main.py
   ```  
2. Select **1) Configure settings**  
3. Enter:

   - **Source directory** (e.g. `/home/user/projects`)  
   - **Backup directory** (e.g. `~/backups`)  
   - **GPG key ID** (the public key for encryption)  
   - **Retention days** (how long to keep `.gpg` backups)  
   - **Exclude patterns** (comma-separated globs)  
   - **Log level** (`DEBUG`, `INFO`, `WARN`)  
   - **SMTP settings** (server, port, username, password, from/to)  
4. The tool saves all settings to `~/.config/backup_main/config.json`.

---

## Usage

### Run Backup

From the menu, choose **2) Run backup**.  
The script will:

1. Load your config and verify paths/GPG key  
2. Scan source dir and load previous snapshot  
3. Archive only changed files to `bkp_<timestamp>.tar.gz`  
4. Encrypt archive to `bkp_<timestamp>.tar.gz.gpg`  
5. Generate `bkp_<timestamp>.tar.gz.gpg.sha256`  
6. Delete old backups beyond retention  
7. Log actions and send optional email  

### Restore Archive

From the menu, choose **3) Restore archive**.  
You will see a numbered list of encrypted backups.  
Select one, then specify a restore folder.  
The script will:

1. Decrypt to a temporary `.tar.gz`  
2. Extract contents into your target directory  
3. Clean up temporary files  

---

## Exclude Patterns

You can filter out files or directories by glob pattern. Examples:

- `*.tmp`  
- `cache/*`  
- `**/*.log`  

Enter patterns in the configuration step (comma-separated).  
Additionally, place a `.backupignore` file in your source directory to version-control ignore rules.

---

## Logging

- **Console**: real-time INFO/WARN/DEBUG messages  
- **File**: `backup.log` in your backup directory, rotated daily  
- **Backup count**: log files retained based on your retention setting  

---

## Email Notifications

On each backup run (success or failure), you can send an email alert:

- **SMTP server** and credentials in config  
- **From** and **To** addresses  
- **Subject** indicates `[OK]` or `[FAIL]` plus timestamp  

---

## .backupignore Support

Create a file named `.backupignore` in your source directory:

```text
# ignore temp files
*.tmp
# ignore cache folder
cache/
```

These patterns are merged with your global exclude list.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository  
2. Create a feature branch  
3. Commit and push your changes  
4. Open a Pull Request  

For major changes, open an issue first to discuss.

---

## License

This project is licensed under the [GPL License](LICENSE).

---

## Author

**Luca Bocaletto** ([@bocaletto-luca](https://github.com/bocaletto-luca))  
Interactive backup enthusiast, Python developer.
