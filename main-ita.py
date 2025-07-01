#!/usr/bin/env python3
"""
backup_main.py v1.0.0

Backup incrementale interattivo in singolo file:
 - configurazione persistente
 - logging file+console
 - snapshot/diff
 - tar(.gz) o pigz
 - crittografia GPG
 - checksum SHA256
 - retention automatica
 - restore interattivo
 - exclude patterns + .backupignore
 - validazione input
 - notifiche email (opzionali)
"""

import os
import sys
import json
import time
import tarfile
import hashlib
import gnupg
import logging
import tempfile
import fnmatch
import glob
import shutil
import subprocess
import smtplib
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from getpass import getpass

VERSION = "1.0.0"
CONFIG_DIR = os.path.expanduser("~/.config/backup_main")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

# -----------------------------------------------------------------------------
# Config Management
# -----------------------------------------------------------------------------
def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

# -----------------------------------------------------------------------------
# Logger Setup
# -----------------------------------------------------------------------------
def setup_logger(log_path, level_str):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    level = getattr(logging, level_str.upper(), logging.INFO)
    logger = logging.getLogger("backup_main")
    logger.setLevel(level)
    if not logger.handlers:
        # File handler
        fh = TimedRotatingFileHandler(log_path, when="midnight", backupCount=cfg['retention_days'])
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        logger.addHandler(fh)
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(ch)
    return logger

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def validate_paths(src, dst, logger):
    if not os.path.isdir(src):
        logger.error(f"src_dir inesistente o non è una cartella: {src}")
        return False
    try:
        os.makedirs(dst, exist_ok=True)
    except Exception as e:
        logger.error(f"Impossibile creare/accesso a backup_dir: {dst} ({e})")
        return False
    return True

def validate_gpg_key(gpg, keyid, logger):
    keys = gpg.list_keys()
    ids = [k['keyid'] for k in keys]
    if keyid not in ids:
        logger.error(f"Chiave GPG '{keyid}' non trovata nel keyring {gpg.gnupghome}")
        return False
    return True

def load_ignore(src):
    ignore_file = os.path.join(src, ".backupignore")
    patterns = []
    if os.path.isfile(ignore_file):
        with open(ignore_file) as f:
            for line in f:
                p = line.strip()
                if p and not p.startswith("#"):
                    patterns.append(p)
    return patterns

# -----------------------------------------------------------------------------
# Snapshot & Diff
# -----------------------------------------------------------------------------
def load_snapshot(path):
    if os.path.exists(path):
        return json.load(open(path))
    return {}

def save_snapshot(snap, path):
    with open(path, "w") as f:
        json.dump(snap, f, indent=2)

def scan_dir(src, excludes):
    snap = {}
    for root, _, files in os.walk(src):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, src)
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            try:
                snap[rel] = os.path.getmtime(full)
            except OSError:
                pass
    return snap

def diff_files(old_snap, new_snap):
    return [f for f, m in new_snap.items()
            if f not in old_snap or old_snap[f] < m]

# -----------------------------------------------------------------------------
# Archiving & Encryption & Checksum & Rotation
# -----------------------------------------------------------------------------
def atomic_replace(tmp, dst):
    os.replace(tmp, dst)

def find_pigz():
    return shutil.which("pigz")

def make_archive(changed, src, dst_archive, logger):
    pigz = find_pigz()
    if pigz:
        logger.debug("Usando pigz per compressione")
        cmd = ["tar", "--use-compress-program", "pigz", "-cf", dst_archive] + changed
        subprocess.check_call(cmd, cwd=src)
    else:
        tmp = dst_archive + ".tmp"
        with tarfile.open(tmp, "w:gz") as tar:
            for rel in changed:
                tar.add(os.path.join(src, rel), arcname=rel)
        atomic_replace(tmp, dst_archive)

def encrypt_file(gpg, inp, outp, recipient, logger):
    tmp = outp + ".tmp"
    with open(inp, "rb") as f:
        status = gpg.encrypt_file(f, recipients=[recipient],
                                  output=tmp, always_trust=True)
    if status.ok:
        atomic_replace(tmp, outp)
        return True
    logger.error(f"GPG encrypt error: {status.stderr}")
    if os.path.exists(tmp):
        os.remove(tmp)
    return False

def write_checksum(path, chk_path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    cs = sha.hexdigest()
    tmp = chk_path + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{cs}  {os.path.basename(path)}\n")
    atomic_replace(tmp, chk_path)
    return cs

def rotate_backups(dst, days, logger):
    cutoff = datetime.now() - timedelta(days=days)
    for f in glob.glob(os.path.join(dst, "bkp_*.tar.gz.gpg")):
        if datetime.fromtimestamp(os.path.getmtime(f)) < cutoff:
            try:
                os.remove(f)
                logger.debug(f"Rotated out {f}")
            except OSError:
                pass

# -----------------------------------------------------------------------------
# Restore
# -----------------------------------------------------------------------------
def restore_archive(gpg, archive_gpg, dest, logger):
    tmp = archive_gpg.rstrip(".gpg")
    with open(archive_gpg, "rb") as f:
        status = gpg.decrypt_file(f, output=tmp)
    if not status.ok:
        raise RuntimeError(status.stderr)
    with tarfile.open(tmp, "r:gz") as tar:
        tar.extractall(dest)
    os.remove(tmp)
    logger.info(f"Restore completo in {dest}")

# -----------------------------------------------------------------------------
# Email Notification
# -----------------------------------------------------------------------------
def send_email(cfg, subject, body, logger):
    try:
        msg = f"Subject: {subject}\nFrom: {cfg['from']}\nTo: {','.join(cfg['to'])}\n\n{body}"
        with smtplib.SMTP(cfg['smtp_server'], cfg['smtp_port']) as s:
            s.starttls()
            s.login(cfg['username'], cfg['password'])
            s.sendmail(cfg['from'], cfg['to'], msg)
        logger.debug("Email notifiche inviata")
    except Exception as e:
        logger.error(f"Errore invio email: {e}")

# -----------------------------------------------------------------------------
# Interactive Menu & Commands
# -----------------------------------------------------------------------------
def prompt_params(existing):
    print("\n--- CONFIGURAZIONE BACKUP ---")
    def ask(key, prompt, default=None, secret=False):
        val = existing.get(key, default) if existing else default
        ans = input(f"{prompt} [{val}]: ").strip()
        if not ans and val is not None:
            return val
        if secret:
            return getpass(prompt + ": ")
        return ans

    src    = ask("src_dir",     "Directory da backuppare", "/")
    dst    = ask("backup_dir",  "Directory destinazione", "~/backup_out")
    rec    = ask("recipient",   "GPG recipient (ID chiave)")
    days   = int(ask("retention_days", "Retention giorni", "7"))
    excl   = ask("excludes",    "Exclude patterns (comma-separated)", "").split(",")
    lvl    = ask("log_level",   "Livello log (DEBUG/INFO/WARN)", "INFO")
    # Email config
    email  = existing.get("notify", {}) if existing else {}
    notify = {
        "smtp_server": ask("smtp_server", "SMTP server", email.get("smtp_server","")),
        "smtp_port":  int(ask("smtp_port",  "SMTP port",     str(email.get("smtp_port",587)))),
        "username":   ask("username",    "SMTP username", email.get("username","")),
        "password":   ask("password",    "SMTP password", "", secret=True),
        "from":       ask("from_addr",   "Email from",    email.get("from","")),
        "to":         ask("to_addrs",    "Email to (comma-separated)", ",".join(email.get("to",[])))
    }
    notify["to"] = [a.strip() for a in notify["to"].split(",") if a.strip()]
    cfg = {
        "src_dir": src,
        "backup_dir": dst,
        "recipient": rec,
        "retention_days": days,
        "excludes": [e.strip() for e in excl if e.strip()],
        "log_level": lvl,
        "notify": notify
    }
    save_config(cfg)
    print("Configurazione salvata in", CONFIG_FILE)
    return cfg

def cmd_run(cfg, logger):
    src = os.path.expanduser(cfg["src_dir"])
    dst = os.path.expanduser(cfg["backup_dir"])
    if not validate_paths(src, dst, logger):
        sys.exit(1)

    log_file = os.path.join(dst, "backup.log")
    logger = setup_logger(log_file, cfg["log_level"])

    gpg_home = os.path.join(dst, "gpg-home")
    os.makedirs(gpg_home, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=gpg_home)
    if not validate_gpg_key(gpg, cfg["recipient"], logger):
        sys.exit(1)

    ignores = cfg["excludes"] + load_ignore(src)
    snap_file = os.path.join(dst, "snapshot.json")
    old_snap = load_snapshot(snap_file)
    new_snap = scan_dir(src, ignores)
    changed  = diff_files(old_snap, new_snap)
    if not changed:
        logger.info("Nessuna modifica: nulla da fare.")
        return

    ts = time.strftime("%Y%m%d%H%M%S")
    arc = os.path.join(dst, f"bkp_{ts}.tar.gz")
    enc = arc + ".gpg"
    chk = enc + ".sha256"

    try:
        logger.info(f"Crea archivio di {len(changed)} file")
        make_archive(changed, src, arc, logger)
        logger.info("Encrypt con GPG")
        if not encrypt_file(gpg, arc, enc, cfg["recipient"], logger):
            raise RuntimeError("GPG encryption failure")
        os.remove(arc)
        cs = write_checksum(enc, chk)
        logger.info(f"Backup completato: {os.path.basename(enc)} (sha256={cs})")
        save_snapshot(new_snap, snap_file)
        rotate_backups(dst, cfg["retention_days"], logger)
        # Notifica
        send_email(cfg["notify"], f"[OK] Backup {ts}", f"Backup ok: {enc}", logger)
    except Exception as e:
        logger.exception("Errore durante il backup")
        send_email(cfg["notify"], f"[FAIL] Backup {ts}", str(e), logger)
        sys.exit(1)

def cmd_restore(cfg, logger):
    dst = os.path.expanduser(cfg["backup_dir"])
    gpg_home = os.path.join(dst, "gpg-home")
    gpg = gnupg.GPG(gnupghome=gpg_home)

    archives = sorted(glob.glob(os.path.join(dst, "bkp_*.tar.gz.gpg")))
    if not archives:
        print("Nessun archivio .gpg trovato in", dst)
        return

    print("\nArchivî disponibili:")
    for i,a in enumerate(archives,1):
        print(f" {i}) {os.path.basename(a)}")
    sel = input(f"Seleziona [1-{len(archives)}]: ").strip()
    try:
        idx = int(sel)-1
        archive = archives[idx]
    except:
        print("Selezione non valida.")
        return

    dest = input("Cartella di destinazione restore [./restore_out]: ").strip() or "./restore_out"
    dest = os.path.abspath(os.path.expanduser(dest))
    os.makedirs(dest, exist_ok=True)

    try:
        restore_archive(gpg, archive, dest, logger)
        print(f"Restore completato in: {dest}")
    except Exception as e:
        logger.exception("Errore restore")
        print("Errore:", e)

def main():
    global cfg
    print(f"backup_main v{VERSION}")
    cfg = load_config()
    logger = logging.getLogger("backup_main")
    while True:
        print("""
MENU:
 1) Configura / Modifica parametri
 2) Esegui backup
 3) Ripristina archivio
 4) Esci
""")
        choice = input("Seleziona [1-4]: ").strip()
        if choice=="1":
            cfg = prompt_params(cfg)
        elif choice=="2":
            if not cfg:
                print("Devi configurare prima (opzione 1).")
                continue
            cmd_run(cfg, logger)
        elif choice=="3":
            if not cfg:
                print("Devi configurare prima (opzione 1).")
                continue
            cmd_restore(cfg, logger)
        elif choice=="4":
            print("Arrivederci!")
            sys.exit(0)
        else:
            print("Scelta non valida.")

if __name__=="__main__":
    try:
        # rich GPG check
        if not shutil.which("gpg"):
            print("Installa GPG (`apt install gnupg`).", file=sys.stderr)
            sys.exit(1)
        main()
    except KeyboardInterrupt:
        print("\nInterrotto dall’utente.") 
