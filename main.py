#!/usr/bin/env python3
"""
backup_main.py

Backup incrementale interattivo in un unico file:
- scelta src/backup con default
- snapshot JSON
- archive .tar.gz solo file modificati
- crittografia GPG
- retention automatica
- checksum SHA256
- restore interattivo
"""

import os, sys, json, time, tarfile, hashlib, gnupg, logging, tempfile, fnmatch, glob
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# Logger
# -----------------------------------------------------------------------------
def setup_logger(log_path, level=logging.INFO):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logger = logging.getLogger("backup")
    logger.setLevel(level)
    if not logger.handlers:
        h = TimedRotatingFileHandler(log_path, when="midnight", backupCount=7)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        logger.addHandler(h)
    return logger

# -----------------------------------------------------------------------------
# Snapshot & Diff
# -----------------------------------------------------------------------------
def load_snapshot(path):
    return json.load(open(path)) if os.path.exists(path) else {}

def save_snapshot(s, path):
    with open(path, "w") as f: json.dump(s, f)

def scan_dir(src, excludes):
    snap = {}
    for root, _, files in os.walk(src):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), src)
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes): continue
            try: snap[rel] = os.path.getmtime(os.path.join(src, rel))
            except: pass
    return snap

def diff_files(old, new):
    return [rel for rel,m in new.items() if rel not in old or m>old[rel]]

# -----------------------------------------------------------------------------
# Archive / Encrypt / Checksum / Rotate
# -----------------------------------------------------------------------------
def atomic_replace(tmp, dst): os.replace(tmp, dst)

def make_archive(changed, src, dst_archive):
    tmp = dst_archive + ".tmp"
    with tarfile.open(tmp, "w:gz") as tar:
        for rel in changed: tar.add(os.path.join(src, rel), arcname=rel)
    atomic_replace(tmp, dst_archive)

def encrypt_file(gpg, inp, outp, recipient):
    tmp = outp + ".tmp"
    with open(inp,"rb") as f:
        st = gpg.encrypt_file(f, recipients=[recipient], output=tmp, always_trust=True)
    if st.ok:
        atomic_replace(tmp, outp)
        return True,""
    if os.path.exists(tmp): os.remove(tmp)
    return False, st.stderr

def write_checksum(path, chk_path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for c in iter(lambda: f.read(65536),b""): h.update(c)
    cs=h.hexdigest()
    tmp=chk_path+".tmp"
    with open(tmp,"w") as f: f.write(f"{cs}  {os.path.basename(path)}\n")
    atomic_replace(tmp, chk_path)
    return cs

def rotate_backups(dst, days):
    cut = datetime.now() - timedelta(days=days)
    for fn in glob.glob(os.path.join(dst,"*.gpg")):
        if datetime.fromtimestamp(os.path.getmtime(fn))<cut:
            try: os.remove(fn)
            except: pass

# -----------------------------------------------------------------------------
# Restore
# -----------------------------------------------------------------------------
def restore_archive(gpg, archive_gpg, dest):
    tmp = archive_gpg.rstrip(".gpg") + ".tar.gz"
    with open(archive_gpg,"rb") as f: st = gpg.decrypt_file(f, output=tmp)
    if not st.ok: raise RuntimeError(st.stderr)
    with tarfile.open(tmp,"r:gz") as tar: tar.extractall(dest)
    os.remove(tmp)

# -----------------------------------------------------------------------------
# Interactive Menu & Config
# -----------------------------------------------------------------------------
def prompt_params():
    d_src = "/"                # default root
    d_dst = os.path.expanduser("~/backup_out")  # default home/backup_out
    print("\nCONFIGURA PARAMETRI:")
    src = input(f"  Src (dir da backuppare) [{d_src}]: ").strip() or d_src
    dst = input(f"  Dst (dir destinazione) [{d_dst}]: ").strip() or d_dst
    rec = input("  GPG recipient (ID chiave): ").strip()
    ret = input("  Retention (giorni) [7]: ").strip() or "7"
    exc = input("  Exclude patterns (csv, es: *.tmp,cache/*) []: ").split(",")
    excludes=[e.strip() for e in exc if e.strip()]
    return {"src":os.path.abspath(src),
            "dst":os.path.abspath(dst),
            "recipient":rec,
            "retention":int(ret),
            "excludes":excludes}

def menu():
    cfg = None
    while True:
        print("""\nMENU:
1) Configura parametri
2) Esegui backup
3) Ripristina archivio
4) Esci""")
        c=input("Seleziona [1-4]: ").strip()
        if c=="1":
            cfg=prompt_params()
            print("Parametri impostati.")
        elif c=="2":
            if not cfg: print("Fai prima opzione 1."); continue
            run_backup(cfg)
        elif c=="3":
            if not cfg: print("Fai prima opzione 1."); continue
            run_restore(cfg)
        elif c=="4":
            print("Bye!"); sys.exit(0)
        else: print("Scelta errata.")

# -----------------------------------------------------------------------------
# Core Operations
# -----------------------------------------------------------------------------
def run_backup(cfg):
    src,dst=cfg["src"],cfg["dst"]
    os.makedirs(dst,exist_ok=True)
    logf=os.path.join(dst,"backup.log")
    logger=setup_logger(logf)
    gpg_home=os.path.join(dst,"gpg-home"); os.makedirs(gpg_home,exist_ok=True)
    gpg=gnupg.GPG(gnupghome=gpg_home)
    if not gpg.version(): print("GPG non trovato."); sys.exit(1)
    logger.info("Avvio backup")
    snapf=os.path.join(dst,"snapshot.json")
    old=load_snapshot(snapf); new=scan_dir(src,cfg["excludes"])
    changed=diff_files(old,new)
    if not changed:
        print("Nessuna modifica."); logger.info("Nessuna modifica."); return

    ts=time.strftime("%Y%m%d%H%M%S")
    arc,enc= os.path.join(dst,f"bkp_{ts}.tar.gz"), None
    enc=arc+".gpg"; chk=enc+".sha256"
    try:
        make_archive(changed,src,arc)
        ok,err=encrypt_file(gpg,arc,enc,cfg["recipient"])
        if not ok: raise RuntimeError(err)
        os.remove(arc)
        cs=write_checksum(enc,chk)
        logger.info(f"Backup {os.path.basename(enc)} (sha256={cs})")
        print(f"Backup ok: {os.path.basename(enc)}")
    except Exception as e:
        logger.exception(f"Errore: {e}")
        print("Errore:",e)
        return
    save_snapshot(new,snapf)
    rotate_backups(dst,cfg["retention"])
    logger.info("Backup terminato")

def run_restore(cfg):
    dst=cfg["dst"]
    gpg_home=os.path.join(dst,"gpg-home")
    gpg=gnupg.GPG(gnupghome=gpg_home)
    archives=sorted(glob.glob(os.path.join(dst,"bkp_*.tar.gz.gpg")))
    if not archives: print("Nessun archivio"); return
    for i,a in enumerate(archives,1): print(f"{i}) {os.path.basename(a)}")
    sel=input(f"Seleziona [1-{len(archives)}]: ").strip()
    try: idx=int(sel)-1; arc=archives[idx]
    except: print("Errato"); return
    dest=input("Cartella restore: ").strip() or os.getcwd()
    os.makedirs(dest,exist_ok=True)
    try:
        restore_archive(gpg,arc,dest)
        print("Restore completato in",dest)
    except Exception as e:
        print("Errore restore:",e)

# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------
if __name__=="__main__":
    if not hasattr(gnupg.GPG(),"version"):
        print("Installa GPG (`apt install gnupg`).", file=sys.stderr)
        sys.exit(1)
    menu()
