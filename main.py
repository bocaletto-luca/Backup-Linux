#!/usr/bin/env python3
"""
backup_main.py

Backup incrementale interattivo in un unico file:
- snapshot JSON
- archive .tar.gz di file modificati
- crittografia GPG
- retention automatico
- checksum SHA256
- restore interattivo
- menu da terminale
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
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# Helper: Logger
# -----------------------------------------------------------------------------

def setup_logger(log_path, level=logging.INFO):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logger = logging.getLogger("backup")
    logger.setLevel(level)
    if not logger.handlers:
        handler = TimedRotatingFileHandler(log_path, when="midnight", backupCount=7)
        fmt = "%(asctime)s %(levelname)s: %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
    return logger

# -----------------------------------------------------------------------------
# Snapshot & Diff
# -----------------------------------------------------------------------------

def load_snapshot(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_snapshot(snapshot, path):
    with open(path, "w") as f:
        json.dump(snapshot, f)

def scan_dir(src, excludes):
    snap = {}
    for root, _, files in os.walk(src):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), src)
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            try:
                snap[rel] = os.path.getmtime(os.path.join(src, rel))
            except OSError:
                pass
    return snap

def diff_files(old, new):
    return [rel for rel, m in new.items()
            if rel not in old or old[rel] < m]

# -----------------------------------------------------------------------------
# Archiving, Encryption, Checksum, Rotation
# -----------------------------------------------------------------------------

def atomic_replace(src, dst):
    os.replace(src, dst)

def make_archive(changed, src, dst_archive):
    tmp = dst_archive + ".tmp"
    with tarfile.open(tmp, "w:gz") as tar:
        for rel in changed:
            tar.add(os.path.join(src, rel), arcname=rel)
    atomic_replace(tmp, dst_archive)

def encrypt_file(gpg, inp, outp, recipient):
    tmp = outp + ".tmp"
    with open(inp, "rb") as f:
        st = gpg.encrypt_file(f, recipients=[recipient],
                              output=tmp, always_trust=True)
    if st.ok:
        atomic_replace(tmp, outp)
        return True, ""
    else:
        if os.path.exists(tmp):
            os.remove(tmp)
        return False, st.stderr

def write_checksum(path, chk_path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    cs = h.hexdigest()
    tmp = chk_path + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{cs}  {os.path.basename(path)}\n")
    atomic_replace(tmp, chk_path)
    return cs

def rotate_backups(dst, days):
    cutoff = datetime.now() - timedelta(days=days)
    for fn in glob.glob(os.path.join(dst, "*.gpg")):
        if datetime.fromtimestamp(os.path.getmtime(fn)) < cutoff:
            try:
                os.remove(fn)
            except OSError:
                pass

# -----------------------------------------------------------------------------
# Restore
# -----------------------------------------------------------------------------

def restore_archive(gpg, archive_gpg, dest):
    tmp = archive_gpg.rstrip(".gpg") + ".tar.gz"
    with open(archive_gpg, "rb") as f:
        st = gpg.decrypt_file(f, output=tmp)
    if not st.ok:
        raise RuntimeError(f"GPG decrypt error: {st.stderr}")
    with tarfile.open(tmp, "r:gz") as tar:
        tar.extractall(dest)
    os.remove(tmp)

# -----------------------------------------------------------------------------
# Interactive Menu
# -----------------------------------------------------------------------------

def prompt_params():
    print("\nConfigura Backup\n" + "-"*20)
    src = input("Directory da backuppare (src_dir): ").strip()
    dst = input("Directory destinazione backup (backup_dir): ").strip()
    recipient = input("GPG recipient (ID chiave): ").strip()
    retention = input("Retention (giorni da conservare) [7]: ").strip() or "7"
    excludes = input(
      "Esclude pattern separati da virgola [es: *.tmp,cache/*]: "
    ).split(",")
    excludes = [e.strip() for e in excludes if e.strip()]
    return {
        "src": os.path.abspath(os.path.expanduser(src)),
        "dst": os.path.abspath(os.path.expanduser(dst)),
        "recipient": recipient,
        "retention": int(retention),
        "excludes": excludes
    }

def menu():
    cfg = None
    while True:
        print("""
Backup Incrementale interattivo
1) Configura parametri
2) Esegui backup
3) Ripristina archivio
4) Esci
""")
        choice = input("Seleziona [1-4]: ").strip()
        if choice == "1":
            cfg = prompt_params()
            print("Parametri salvati in memoria per questa sessione.")
        elif choice == "2":
            if not cfg:
                print("Devi prima configurare i parametri (opzione 1).")
                continue
            run_backup(cfg)
        elif choice == "3":
            if not cfg:
                print("Devi prima configurare i parametri (opzione 1).")
                continue
            run_restore(cfg)
        elif choice == "4":
            print("Esco. Alla prossima!")
            sys.exit(0)
        else:
            print("Scelta non valida, riprova.")

# -----------------------------------------------------------------------------
# Core Commands
# -----------------------------------------------------------------------------

def run_backup(cfg):
    src, dst = cfg["src"], cfg["dst"]
    os.makedirs(dst, exist_ok=True)

    # Logger & GPG
    logf = os.path.join(dst, "backup.log")
    logger = setup_logger(logf)
    gpg_home = os.path.join(dst, "gpg-home")
    os.makedirs(gpg_home, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=gpg_home)

    logger.info("Avvio backup")
    snap_file = os.path.join(dst, "snapshot.json")
    old = load_snapshot(snap_file)
    new = scan_dir(src, cfg["excludes"])
    changed = diff_files(old, new)
    if not changed:
        print("Nessuna modifica: nessun backup creato.")
        logger.info("Nessuna modifica.")
        return

    ts = time.strftime("%Y%m%d%H%M%S")
    arc = os.path.join(dst, f"bkp_{ts}.tar.gz")
    enc = arc + ".gpg"
    chk = enc + ".sha256"

    try:
        make_archive(changed, src, arc)
        ok, err = encrypt_file(gpg, arc, enc, cfg["recipient"])
        if not ok:
            raise RuntimeError(f"GPG error: {err}")
        os.remove(arc)
        cs = write_checksum(enc, chk)
        logger.info(f"Backup creato: {os.path.basename(enc)} (sha256={cs})")
        print(f"Backup completato: {os.path.basename(enc)}")
    except Exception as e:
        logger.exception(f"Errore backup: {e}")
        print(f"Errore durante il backup: {e}")
        return

    save_snapshot(new, snap_file)
    rotate_backups(dst, cfg["retention"])
    logger.info("Backup terminato.")

def run_restore(cfg):
    dst = cfg["dst"]
    gpg_home = os.path.join(dst, "gpg-home")
    gpg = gnupg.GPG(gnupghome=gpg_home)

    archives = sorted(glob.glob(os.path.join(dst, "bkp_*.tar.gz.gpg")))
    if not archives:
        print("Nessun archivio .gpg trovato in", dst)
        return

    print("\nArchivî trovati:")
    for i, a in enumerate(archives, 1):
        print(f"{i}) {os.path.basename(a)}")
    sel = input(f"Seleziona [1-{len(archives)}]: ").strip()
    try:
        idx = int(sel) - 1
        archive = archives[idx]
    except:
        print("Selezione non valida.")
        return

    dest = input("Cartella di destinazione restore: ").strip()
    dest = os.path.abspath(os.path.expanduser(dest))
    os.makedirs(dest, exist_ok=True)

    try:
        restore_archive(gpg, archive, dest)
        print(f"Restore completato in {dest}")
    except Exception as e:
        print(f"Errore in fase di restore: {e}")

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    if not hasattr(gnupg.GPG(), "version"):
        print("GPG non trovato: installa 'gpg' e riprova.", file=sys.stderr)
        sys.exit(1)
    menu()
