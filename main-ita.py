#!/usr/bin/env python3
"""
backup_main.py v1.0.0

Utility interattiva per backup incrementale in un solo file:
 - configurazione persistente (~/.config/backup_main/config.json)
 - logging su console e file rotanti giornalieri
 - snapshot / diff
 - compressione tar(.gz) o pigz
 - crittografia GPG
 - checksum SHA256
 - rotazione automatica dei backup
 - restore interattivo
 - pattern di esclusione + .backupignore
 - validazione input
 - notifiche email opzionali
"""

import os
import sys
import json
import time
import tarfile
import hashlib
import gnupg
import logging
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


def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def setup_logger(log_path, level_str, backup_count=7):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    livello = getattr(logging, level_str.upper(), logging.INFO)
    logger = logging.getLogger("backup_main")
    logger.setLevel(livello)
    if not logger.handlers:
        # Handler per file di log rotante
        fh = TimedRotatingFileHandler(log_path, when="midnight", backupCount=backup_count)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        logger.addHandler(fh)
        # Handler per console
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(ch)
    return logger


def validate_paths(src, dst, logger):
    if not os.path.isdir(src):
        logger.error(f"Directory di origine inesistente: {src}")
        return False
    try:
        os.makedirs(dst, exist_ok=True)
    except Exception as e:
        logger.error(f"Impossibile creare/accedere a directory di backup {dst}: {e}")
        return False
    return True


def validate_gpg_key(gpg, keyid, logger):
    chiavi = gpg.list_keys()
    if keyid not in [k["keyid"] for k in chiavi]:
        logger.error(f"Chiave GPG '{keyid}' non presente in {gpg.gnupghome}")
        return False
    return True


def load_ignore(src):
    ignora = []
    path = os.path.join(src, ".backupignore")
    if os.path.isfile(path):
        with open(path) as f:
            for linea in f:
                p = linea.strip()
                if p and not p.startswith("#"):
                    ignora.append(p)
    return ignora


def load_snapshot(path):
    if os.path.isfile(path):
        return json.load(open(path))
    return {}


def save_snapshot(snap, path):
    with open(path, "w") as f:
        json.dump(snap, f, indent=2)


def scan_dir(src, excludes):
    snapshot = {}
    for root, _, files in os.walk(src):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, src)
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            try:
                snapshot[rel] = os.path.getmtime(full)
            except OSError:
                pass
    return snapshot


def diff_files(old_snap, new_snap):
    return [f for f, m in new_snap.items() if f not in old_snap or old_snap[f] < m]


def atomic_replace(tmp, dst):
    os.replace(tmp, dst)


def find_pigz():
    return shutil.which("pigz")


def make_archive(changed, src, dst_archive, logger):
    pigz = find_pigz()
    if pigz:
        logger.debug("Uso di pigz per compressione parallela")
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
        st = gpg.encrypt_file(f,
                              recipients=[recipient],
                              output=tmp,
                              always_trust=True)
    if st.ok:
        atomic_replace(tmp, outp)
        return True
    logger.error(f"Errore crittografia GPG: {st.stderr}")
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
                logger.debug(f"Rimosso backup vecchio: {f}")
            except OSError:
                pass


def restore_archive(gpg, archive, dest, logger):
    tmp = archive[:-4]  # rimuove ".gpg"
    with open(archive, "rb") as f:
        st = gpg.decrypt_file(f, output=tmp)
    if not st.ok:
        raise RuntimeError(st.stderr)
    with tarfile.open(tmp, "r:gz") as tar:
        tar.extractall(dest)
    os.remove(tmp)
    logger.info(f"Ripristino completato in {dest}")


def send_email(cfg, subject, body, logger):
    try:
        msg = f"Subject: {subject}\nFrom: {cfg['from']}\nTo: {','.join(cfg['to'])}\n\n{body}"
        with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as s:
            s.starttls()
            s.login(cfg["username"], cfg["password"])
            s.sendmail(cfg["from"], cfg["to"], msg)
        logger.debug("Email notifica inviata")
    except Exception as e:
        logger.error(f"Invio email fallito: {e}")


def prompt_params(existing):
    print("\n=== CONFIGURAZIONE BACKUP ===")
    def ask(key, prompt, default=None, secret=False):
        val = existing.get(key, default) if existing else default
        if secret:
            ans = getpass(f"{prompt} [{val if val else ''}]: ")
        else:
            ans = input(f"{prompt} [{val}]: ").strip()
        return ans if ans else val

    src = ask("src_dir", "Directory di origine", "/")
    dst = ask("backup_dir", "Directory di destinazione", "~/backup_out")
    rec = ask("recipient", "ID chiave GPG destinatario")
    days = int(ask("retention_days", "Giorni di retention", "7"))
    excl = ask("excludes", "Pattern di esclusione (separati da virgola)", "")
    lvl = ask("log_level", "Livello di log (DEBUG/INFO/WARN)", "INFO")

    email = existing.get("notify", {}) if existing else {}
    notify = {
        "smtp_server": ask("smtp_server", "Server SMTP", email.get("smtp_server", "")),
        "smtp_port":   int(ask("smtp_port", "Porta SMTP", str(email.get("smtp_port", 587)))),
        "username":    ask("username", "Utente SMTP", email.get("username", "")),
        "password":    ask("password", "Password SMTP", "", secret=True),
        "from":        ask("from_addr", "Email mittente", email.get("from", "")),
        "to":          ask("to_addrs", "Email destinatari (csv)", ",".join(email.get("to", [])))
    }
    notify["to"] = [x.strip() for x in notify["to"].split(",") if x.strip()]

    cfg = {
        "src_dir": src,
        "backup_dir": dst,
        "recipient": rec,
        "retention_days": days,
        "excludes": [x.strip() for x in excl.split(",") if x.strip()],
        "log_level": lvl,
        "notify": notify
    }
    save_config(cfg)
    print(f"Configurazione salvata in {CONFIG_FILE}")
    return cfg


def cmd_run(cfg):
    src = os.path.expanduser(cfg["src_dir"])
    dst = os.path.expanduser(cfg["backup_dir"])
    logger = setup_logger(os.path.join(dst, "backup.log"),
                          cfg["log_level"],
                          cfg["retention_days"])
    if not validate_paths(src, dst, logger):
        sys.exit(1)

    gpg_home = os.path.join(dst, "gpg-home")
    os.makedirs(gpg_home, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=gpg_home)
    if not validate_gpg_key(gpg, cfg["recipient"], logger):
        sys.exit(1)

    ignores = cfg["excludes"] + load_ignore(src)
    snap_file = os.path.join(dst, "snapshot.json")
    old_snap = load_snapshot(snap_file)
    new_snap = scan_dir(src, ignores)
    changed = diff_files(old_snap, new_snap)

    if not changed:
        logger.info("Nessuna modifica rilevata; nessun backup eseguito.")
        print("Nessuna modifica rilevata.")
        return

    ts = time.strftime("%Y%m%d%H%M%S")
    archive = os.path.join(dst, f"bkp_{ts}.tar.gz")
    encrypted = archive + ".gpg"
    checksum = encrypted + ".sha256"

    try:
        logger.info(f"Creazione archivio di {len(changed)} file")
        make_archive(changed, src, archive, logger)
        logger.info("Crittografia archivio con GPG")
        if not encrypt_file(gpg, archive, encrypted, cfg["recipient"], logger):
            raise RuntimeError("Crittografia GPG fallita")
        os.remove(archive)
        cs = write_checksum(encrypted, checksum)
        logger.info(f"Backup completato: {os.path.basename(encrypted)} (SHA256={cs})")
        save_snapshot(new_snap, snap_file)
        rotate_backups(dst, cfg["retention_days"], logger)
        send_email(cfg["notify"],
                   f"[OK] Backup {ts}",
                   f"Backup riuscito: {encrypted}\nSHA256={cs}",
                   logger)
    except Exception as e:
        logger.exception("Errore durante il backup")
        send_email(cfg["notify"],
                   f"[FALLITO] Backup {ts}",
                   str(e),
                   logger)
        sys.exit(1)


def cmd_restore(cfg):
    dst = os.path.expanduser(cfg["backup_dir"])
    logger = setup_logger(os.path.join(dst, "backup.log"),
                          cfg["log_level"],
                          cfg["retention_days"])
    gpg_home = os.path.join(dst, "gpg-home")
    gpg = gnupg.GPG(gnupghome=gpg_home)

    archives = sorted(glob.glob(os.path.join(dst, "bkp_*.tar.gz.gpg")))
    if not archives:
        print("Nessun archivio crittografato trovato in", dst)
        return

    print("\nBackup disponibili:")
    for i, a in enumerate(archives, 1):
        print(f"{i}) {os.path.basename(a)}")
    sel = input(f"Seleziona [1-{len(archives)}]: ").strip()
    try:
        idx = int(sel) - 1
        archive = archives[idx]
    except:
        print("Selezione non valida.")
        return

    dest = input("Cartella di restore [./restore_out]: ").strip() or "./restore_out"
    dest = os.path.abspath(os.path.expanduser(dest))
    os.makedirs(dest, exist_ok=True)

    try:
        restore_archive(gpg, archive, dest, logger)
        print(f"Ripristino completato in {dest}")
    except Exception as e:
        logger.exception("Errore restore")
        print("Errore durante il ripristino:", e)


def main():
    print(f"backup_main v{VERSION}")
    cfg = load_config()
    while True:
        print("""
MENU:
 1) Configura impostazioni
 2) Esegui backup
 3) Ripristina archivio
 4) Esci
""")
        scelta = input("Seleziona [1-4]: ").strip()
        if scelta == "1":
            cfg = prompt_params(cfg)
        elif scelta == "2":
            if not cfg:
                print("Devi prima configurare (opzione 1).")
                continue
            cmd_run(cfg)
        elif scelta == "3":
            if not cfg:
                print("Devi prima configurare (opzione 1).")
                continue
            cmd_restore(cfg)
        elif scelta == "4":
            print("Arrivederci!")
            sys.exit(0)
        else:
            print("Scelta non valida.")


if __name__ == "__main__":
    if not shutil.which("gpg"):
        print("Installa GPG (es. sudo apt install gnupg).", file=sys.stderr)
        sys.exit(1)
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente.")
