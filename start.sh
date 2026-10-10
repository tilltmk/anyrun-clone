#!/usr/bin/env bash
#
# start.sh - Launcher fuer AnyRun Clone (REAL Analysis Edition)
#
# Prueft die komplette Laufzeitumgebung (Python, Abhaengigkeiten, libvirt,
# isoliertes Netz, VM-Template, Snapshot, Ports) und startet erst danach
# app.py. Ohne gesunde Umgebung laeuft keine dynamische Analyse - lieber
# vorher sauber abbrechen als mitten im Sample-Run scheitern.
#
#   ./start.sh                 # Preflight + Server starten
#   ./start.sh --check         # nur pruefen, nichts aendern, nichts starten
#   ./start.sh --static-only   # ohne KVM, nur statische Analyse
#   ./start.sh --help          # alle Optionen
#
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$PROJECT_DIR"

# --------------------------------------------------------------------------
# Defaults - alle per Umgebungsvariable oder CLI-Flag ueberschreibbar
# --------------------------------------------------------------------------
HOST="${ANYRUN_HOST:-127.0.0.1}"       # bewusst nicht 0.0.0.0: Malware-UI
PORT="${ANYRUN_PORT:-5000}"
DEBUG="${ANYRUN_DEBUG:-0}"
STATIC_ONLY="${ANYRUN_STATIC_ONLY:-0}"
LIBVIRT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"
NETWORK_NAME="isolated"
LOG_FILE="${ANYRUN_LOG:-}"

CHECK_ONLY=0
RESET_VM=0
ALLOW_DIRTY_VM=0
SHUTDOWN_VM_ON_EXIT=1
SKIP_DEPS=0

SETUP_JSON="config/setup.json"
PY=""
PRIV=""
FAILURES=0
WARNINGS=0
VM_DOMAIN=""
VM_SNAPSHOT=""

# --------------------------------------------------------------------------
# Ausgabe
# --------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RST=$'\033[0m'; C_DIM=$'\033[2m'; C_B=$'\033[1m'
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_CYN=$'\033[36m'
else
    C_RST=""; C_DIM=""; C_B=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""
fi

section() { printf '\n%s== %s ==%s\n' "$C_B$C_CYN" "$1" "$C_RST"; }
ok()      { printf '  %s[ OK ]%s %s\n' "$C_GRN" "$C_RST" "$1"; }
info()    { printf '  %s[ .. ]%s %s\n' "$C_DIM" "$C_RST" "$1"; }
warn()    { printf '  %s[WARN]%s %s\n' "$C_YEL" "$C_RST" "$1"; WARNINGS=$((WARNINGS + 1)); }
fail()    { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_RST" "$1"; FAILURES=$((FAILURES + 1)); }
hint()    { printf '         %s-> %s%s\n' "$C_DIM" "$1" "$C_RST"; }
die()     { printf '\n%s[ABBRUCH]%s %s\n' "$C_RED$C_B" "$C_RST" "$1" >&2; exit 1; }

usage() {
    cat <<EOF
${C_B}AnyRun Clone - Startskript${C_RST}

  ./start.sh [OPTIONEN]

Netzwerk/Server:
  --host ADDR           Bind-Adresse (Default: $HOST)
  --port N              Port (Default: $PORT)
  --listen-all          Kurzform fuer --host 0.0.0.0 (Achtung: UI oeffentlich)
  --debug               Flask-Debug an (Reloader bleibt aus, s. Kommentar)
  --log DATEI           Ausgabe zusaetzlich in DATEI schreiben

Analyse-Modus:
  --static-only         KVM ueberspringen, nur statische Analyse
  --dynamic             Dynamische Analyse erzwingen (Default, wenn VM ok)
  --reset-vm            VM vor dem Start auf Snapshot '$VM_SNAPSHOT' zuruecksetzen
  --allow-dirty-vm      Dynamische Analyse auch ohne Clean-Snapshot zulassen
  --keep-vm-running     VM beim Beenden des Servers NICHT herunterfahren

Sonstiges:
  --check               Nur Preflight (read-only), kein Start, keine Aenderung
  --skip-deps           Python-Modulpruefung ueberspringen (schnellerer Start)
  -h, --help            Diese Hilfe

Umgebungsvariablen: ANYRUN_HOST, ANYRUN_PORT, ANYRUN_DEBUG, ANYRUN_STATIC_ONLY,
ANYRUN_PYTHON, ANYRUN_LOG, LIBVIRT_DEFAULT_URI, SECRET_KEY
EOF
}

# --------------------------------------------------------------------------
# Argumente
# --------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)            HOST="${2:?--host braucht eine Adresse}"; shift 2 ;;
        --port)            PORT="${2:?--port braucht eine Nummer}"; shift 2 ;;
        --listen-all)      HOST="0.0.0.0"; shift ;;
        --debug)           DEBUG=1; shift ;;
        --log)             LOG_FILE="${2:?--log braucht einen Pfad}"; shift 2 ;;
        --static-only)     STATIC_ONLY=1; shift ;;
        --dynamic)         STATIC_ONLY=0; shift ;;
        --reset-vm)        RESET_VM=1; shift ;;
        --allow-dirty-vm)  ALLOW_DIRTY_VM=1; shift ;;
        --keep-vm-running) SHUTDOWN_VM_ON_EXIT=0; shift ;;
        --check)           CHECK_ONLY=1; shift ;;
        --skip-deps)       SKIP_DEPS=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *)                 usage >&2; die "Unbekannte Option: $1" ;;
    esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] || die "Port muss numerisch sein: $PORT"

if [[ -n "$LOG_FILE" ]]; then
    mkdir -p "$(dirname -- "$LOG_FILE")"
    exec > >(tee -a -- "$LOG_FILE") 2>&1
    printf '%s--- Lauf gestartet: %s ---%s\n' "$C_DIM" "$(date -Is)" "$C_RST"
fi

# --------------------------------------------------------------------------
# 1. Privilegien-Helfer
#    Auf diesem System existiert kein sudo-Binary (opendoas). Aliase greifen
#    in Skripten nicht, also wird das vorhandene Tool ermittelt.
# --------------------------------------------------------------------------
detect_priv() {
    local p
    for p in doas sudo pkexec; do
        if command -v "$p" >/dev/null 2>&1; then PRIV="$p"; return; fi
    done
    PRIV=""
}

as_root() {
    if [[ $EUID -eq 0 ]]; then "$@"; return; fi
    [[ -n "$PRIV" ]] || return 127
    "$PRIV" "$@"
}

# --------------------------------------------------------------------------
# 2. Python-Interpreter
# --------------------------------------------------------------------------
check_python() {
    section "Python"
    local cand=()
    [[ -n "${ANYRUN_PYTHON:-}" ]] && cand+=("$ANYRUN_PYTHON")
    cand+=("$PROJECT_DIR/venv/bin/python" "$PROJECT_DIR/.venv/bin/python")
    cand+=(python3.14 python3.13 python3.12 python3)

    local c
    for c in "${cand[@]}"; do
        if command -v "$c" >/dev/null 2>&1 || [[ -x "$c" ]]; then
            if "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
                PY="$c"; break
            fi
        fi
    done

    if [[ -z "$PY" ]]; then
        fail "Kein Python >= 3.11 gefunden"
        hint "Kandidaten geprueft: ${cand[*]}"
        return
    fi

    local ver; ver="$("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
    ok "Python $ver ($("$PY" -c 'import sys; print(sys.executable)'))"
    [[ "$PY" == *"/venv/bin/python" || "$PY" == *"/.venv/bin/python" ]] \
        && ok "venv aktiv" \
        || info "kein venv - System-Python wird genutzt"
}

check_dependencies() {
    section "Python-Abhaengigkeiten"
    if [[ $SKIP_DEPS -eq 1 ]]; then
        info "uebersprungen (--skip-deps)"
        return
    fi
    [[ -n "$PY" ]] || { fail "ohne Interpreter nicht pruefbar"; return; }

    # Importnamen != Paketnamen (python-magic -> magic, yara-python -> yara)
    local report
    report="$("$PY" - <<'PY'
import importlib.util as u

REQUIRED = {
    "flask": "Flask", "flask_sqlalchemy": "Flask-SQLAlchemy",
    "flask_socketio": "Flask-SocketIO", "werkzeug": "Werkzeug",
    "psutil": "psutil", "magic": "python-magic", "PIL": "Pillow",
    "yara": "yara-python", "pefile": "pefile", "websockets": "websockets",
}
OPTIONAL = {
    "libvirt": "libvirt-python (KVM-Verwaltung)",
    "scapy": "scapy (Netzwerk-Capture)",
    "eventlet": "eventlet (Async)",
    "ffmpeg": "ffmpeg-python (Videoaufnahme)",
}

for mod, pkg in REQUIRED.items():
    print(("MISSING_REQ" if u.find_spec(mod) is None else "HAVE"), pkg)
for mod, pkg in OPTIONAL.items():
    print(("MISSING_OPT" if u.find_spec(mod) is None else "HAVE"), pkg)
PY
)" || { fail "Modulpruefung abgebrochen"; return; }

    local missing_req=() missing_opt=() have=0 state pkg
    while read -r state pkg; do
        case "$state" in
            HAVE)        have=$((have + 1)) ;;
            MISSING_REQ) missing_req+=("$pkg") ;;
            MISSING_OPT) missing_opt+=("$pkg") ;;
        esac
    done <<< "$report"

    if [[ ${#missing_req[@]} -gt 0 ]]; then
        fail "Pflichtmodule fehlen: ${missing_req[*]}"
        hint "$PY -m pip install -r requirements.txt"
    else
        ok "$have Module vorhanden, alle Pflichtmodule erfuellt"
    fi

    if [[ ${#missing_opt[@]} -gt 0 ]]; then
        warn "optional fehlt: ${missing_opt[*]}"
        hint "ohne libvirt/scapy sind dynamische Analyse bzw. Capture eingeschraenkt"
    fi
}

# --------------------------------------------------------------------------
# 3. Verzeichnisse, Datenbank, Secret
# --------------------------------------------------------------------------
check_workspace() {
    section "Arbeitsverzeichnisse"
    local d
    for d in uploads results config instance yara_rules static/css static/js; do
        if [[ -d "$d" ]]; then
            ok "$d/"
        elif [[ $CHECK_ONLY -eq 1 ]]; then
            warn "$d/ fehlt (wuerde beim Start erstellt)"
        else
            mkdir -p "$d" && ok "$d/ erstellt"
        fi
    done

    local rules; rules=$(find yara_rules -name '*.yar' -o -name '*.yara' 2>/dev/null | wc -l)
    if [[ "$rules" -gt 0 ]]; then
        ok "$rules YARA-Regeldatei(en)"
    else
        warn "keine YARA-Regeln in yara_rules/ - Scan liefert keine Treffer"
    fi

    [[ -f instance/anyrun.db ]] \
        && ok "SQLite-DB vorhanden ($(du -h instance/anyrun.db | cut -f1))" \
        || info "DB fehlt - db.create_all() legt sie beim Start an"
}

check_secret() {
    section "SECRET_KEY"
    if [[ -f .env ]]; then
        set -a; # shellcheck disable=SC1091
        source ./.env; set +a
        info ".env geladen"
    fi

    if [[ -n "${SECRET_KEY:-}" && "$SECRET_KEY" != "change-this-in-production" ]]; then
        ok "SECRET_KEY gesetzt (${#SECRET_KEY} Zeichen, Wert wird nicht geloggt)"
        return
    fi

    if [[ $CHECK_ONLY -eq 1 ]]; then
        warn "kein SECRET_KEY - Start wuerde einen generieren und in .env ablegen"
        return
    fi

    [[ -n "$PY" ]] || { warn "ohne Python kein Key generierbar"; return; }
    SECRET_KEY="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(48))')"
    umask 077
    printf 'SECRET_KEY=%s\n' "$SECRET_KEY" >> .env
    chmod 600 .env
    export SECRET_KEY
    ok "neuer SECRET_KEY generiert und in .env hinterlegt (chmod 600, gitignored)"
}

# --------------------------------------------------------------------------
# 4. Port
# --------------------------------------------------------------------------
check_ports() {
    section "Ports"
    local occupied=""
    if command -v ss >/dev/null 2>&1; then
        occupied="$(ss -ltnH "sport = :$PORT" 2>/dev/null || true)"
    fi

    if [[ -n "$occupied" ]]; then
        fail "Port $PORT ist belegt"
        hint "$(printf '%s' "$occupied" | tr -s ' ' | cut -d' ' -f4,6)"
        hint "anderen Port waehlen: ./start.sh --port 5050"
    else
        ok "Port $PORT frei (Web-UI + WebSocket)"
    fi

    # vnc_proxy.py mappt VNC 5900+n auf WebSocket 6000+n
    if [[ $STATIC_ONLY -eq 0 ]] && command -v ss >/dev/null 2>&1; then
        local ws; ws="$(ss -ltnH "sport = :6000" 2>/dev/null || true)"
        [[ -n "$ws" ]] \
            && warn "Port 6000 belegt - VNC-WebSocket-Proxy kann kollidieren" \
            || ok "Port 6000 frei (VNC-WebSocket-Proxy)"
    fi
}

# --------------------------------------------------------------------------
# 5. KVM / libvirt
#    Wichtig: nicht 'systemctl is-active' pruefen. libvirt laeuft hier per
#    Socket-Aktivierung und meldet 'inactive', obwohl es nutzbar ist. Die
#    einzige verlaessliche Pruefung ist ein echter Verbindungsversuch.
# --------------------------------------------------------------------------
libvirt_reachable() {
    virsh -c "$LIBVIRT_URI" -q version >/dev/null 2>&1
}

check_kvm() {
    section "KVM / libvirt"

    if [[ ! -e /dev/kvm ]]; then
        warn "/dev/kvm fehlt - keine Hardware-Virtualisierung"
        hint "VT-x/AMD-V im BIOS pruefen; Fallback: --static-only"
        STATIC_ONLY=1
        return
    fi
    [[ -r /dev/kvm && -w /dev/kvm ]] \
        && ok "/dev/kvm nutzbar" \
        || warn "/dev/kvm nicht beschreibbar - Gruppe 'kvm' pruefen"

    local b
    for b in qemu-system-x86_64 qemu-img virsh; do
        command -v "$b" >/dev/null 2>&1 \
            && ok "$b: $(command -v "$b")" \
            || { fail "$b fehlt"; hint "dnf install qemu-kvm libvirt-client"; }
    done

    command -v websockify >/dev/null 2>&1 \
        && ok "websockify: $(command -v websockify)" \
        || warn "websockify fehlt - Live-VNC-Stream evtl. eingeschraenkt"

    if libvirt_reachable; then
        ok "libvirt erreichbar ($LIBVIRT_URI, $(virsh -c "$LIBVIRT_URI" -q version 2>/dev/null | head -1))"
    elif [[ $CHECK_ONLY -eq 1 ]]; then
        fail "libvirt unter $LIBVIRT_URI nicht erreichbar"
        hint "Start wuerde versuchen: systemctl start libvirtd.socket"
        return
    else
        info "libvirt nicht erreichbar - Socket wird gestartet"
        detect_priv
        local unit
        for unit in virtqemud.socket libvirtd.socket libvirtd.service; do
            if as_root systemctl start "$unit" >/dev/null 2>&1; then
                sleep 1
                libvirt_reachable && { ok "libvirt via $unit gestartet"; break; }
            fi
        done
        if ! libvirt_reachable; then
            fail "libvirt bleibt unerreichbar"
            hint "${PRIV:-sudo} systemctl start libvirtd.socket  (oder --static-only)"
            return
        fi
    fi

    id -nG | tr ' ' '\n' | grep -qx libvirt \
        && ok "Benutzer in Gruppe 'libvirt'" \
        || warn "nicht in Gruppe 'libvirt' - polkit fragt evtl. nach Rechten"
}

check_network() {
    section "Isoliertes Analyse-Netz"
    libvirt_reachable || { fail "ohne libvirt nicht pruefbar"; return; }

    local state
    state="$(virsh -c "$LIBVIRT_URI" -q net-info "$NETWORK_NAME" 2>/dev/null \
             | awk -F': *' 'tolower($1) ~ /aktiv|active/ {print tolower($2)}')"

    if [[ -z "$state" ]]; then
        fail "Netz '$NETWORK_NAME' existiert nicht"
        hint "Setup-Wizard unter /setup anlegen lassen oder: virsh net-define ..."
        return
    fi

    if [[ "$state" == "ja" || "$state" == "yes" ]]; then
        ok "Netz '$NETWORK_NAME' aktiv"
    elif [[ $CHECK_ONLY -eq 1 ]]; then
        warn "Netz '$NETWORK_NAME' inaktiv (Start wuerde es aktivieren)"
    else
        virsh -c "$LIBVIRT_URI" -q net-start "$NETWORK_NAME" >/dev/null 2>&1 \
            && ok "Netz '$NETWORK_NAME' gestartet" \
            || fail "Netz '$NETWORK_NAME' liess sich nicht starten"
    fi

    # Isolation verifizieren: ein <forward>-Element heisst Weg nach draussen.
    local fwd
    fwd="$(virsh -c "$LIBVIRT_URI" -q net-dumpxml "$NETWORK_NAME" 2>/dev/null \
           | grep -o '<forward[^>]*mode=.[a-z]*' | grep -o '[a-z]*$' || true)"
    if [[ -n "$fwd" ]]; then
        warn "Netz hat forward mode='$fwd' - Samples koennten nach aussen kommunizieren"
        hint "fuer echte Isolation das <forward>-Element entfernen"
    else
        ok "kein Forwarding definiert - Netz ist isoliert"
    fi
}

# --------------------------------------------------------------------------
# 6. VM-Template + Snapshot-Politik
#
#    Richtlinie (hier bewusst zentral, leicht aenderbar):
#      * VM laeuft noch (abgestuerzte Session) -> hart zerstoeren, danach auf
#        Clean-Snapshot zuruecksetzen. Ein weiterlaufendes Sample darf nicht
#        in die naechste Analyse hineinwirken.
#      * Clean-Snapshot fehlt -> HARTER Abbruch fuer dynamische Analyse, kein
#        stilles Zurueckfallen auf statisch. Analyse auf verschmutzter Platte
#        liefert wertlose Ergebnisse. Bewusst erlaubbar mit --allow-dirty-vm.
# --------------------------------------------------------------------------
read_vm_template() {
    [[ -f "$SETUP_JSON" && -n "$PY" ]] || return 0
    local out
    out="$("$PY" - "$SETUP_JSON" <<'PY' 2>/dev/null || true
import json, sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        cfg = json.load(fh)
except (OSError, ValueError) as exc:
    print("ERROR", exc)
    raise SystemExit(0)

print("STATIC_ONLY", "1" if cfg.get("static_only") else "0")
print("SETUP_COMPLETE", "1" if cfg.get("setup_complete") else "0")
for os_type, tpl in (cfg.get("vm_templates") or {}).items():
    print("TEMPLATE", os_type, tpl.get("name", ""), tpl.get("status", "?"),
          tpl.get("snapshot", ""), tpl.get("disk_path", ""),
          "1" if tpl.get("needs_installation") else "0")
PY
)"
    printf '%s' "$out"
}

check_vm_template() {
    section "VM-Template"
    local data; data="$(read_vm_template)"

    if [[ -z "$data" ]]; then
        warn "$SETUP_JSON nicht lesbar - Setup-Wizard unter /setup noetig"
        return
    fi

    local kind rest
    while read -r kind rest; do
        [[ -n "$kind" ]] || continue
        case "$kind" in
            ERROR)          fail "$SETUP_JSON fehlerhaft: $rest"; return ;;
            SETUP_COMPLETE) [[ "$rest" == "1" ]] \
                                && ok "Setup abgeschlossen" \
                                || warn "Setup unvollstaendig - UI startet mit Wizard (/setup)" ;;
            STATIC_ONLY)    [[ "$rest" == "1" ]] && {
                                info "Konfiguration ist auf Static-Only gesetzt"
                                STATIC_ONLY=1
                            } ;;
            TEMPLATE)
                local os_type name status snap disk needs_inst
                read -r os_type name status snap disk needs_inst <<< "$rest"
                ok "Template '$os_type': Domain=$name Status=$status"
                if [[ "$needs_inst" == "1" ]]; then
                    warn "OS-Installation noch nicht abgeschlossen (needs_installation)"
                    hint "Installation via VNC im Setup-Wizard beenden"
                fi
                [[ -n "$disk" ]] && info "Disk: $disk"
                # Erstes brauchbares Template fuer die VM-Pruefung merken
                if [[ -z "$VM_DOMAIN" && -n "$name" ]]; then
                    VM_DOMAIN="$name"; VM_SNAPSHOT="$snap"
                fi
                ;;
        esac
    done <<< "$data"

    [[ -n "$VM_DOMAIN" ]] || warn "kein VM-Template konfiguriert - nur statische Analyse moeglich"
}

check_vm_state() {
    [[ $STATIC_ONLY -eq 0 && -n "$VM_DOMAIN" ]] || return 0
    libvirt_reachable || return 0

    section "VM-Zustand ($VM_DOMAIN)"

    if ! virsh -c "$LIBVIRT_URI" -q dominfo "$VM_DOMAIN" >/dev/null 2>&1; then
        fail "Domain '$VM_DOMAIN' existiert in libvirt nicht"
        hint "Template im Setup-Wizard neu anlegen oder --static-only nutzen"
        return
    fi

    local state
    state="$(virsh -c "$LIBVIRT_URI" -q domstate "$VM_DOMAIN" 2>/dev/null || echo unbekannt)"
    info "Status: $state"

    # Snapshot-Inventar
    local snaps have_snap=0
    snaps="$(virsh -c "$LIBVIRT_URI" -q snapshot-list --name "$VM_DOMAIN" 2>/dev/null || true)"
    if [[ -n "$VM_SNAPSHOT" ]] && grep -qx -- "$VM_SNAPSHOT" <<< "$snaps"; then
        have_snap=1
        ok "Clean-Snapshot '$VM_SNAPSHOT' vorhanden"
    elif [[ -n "$snaps" ]]; then
        warn "Snapshot '$VM_SNAPSHOT' fehlt; vorhanden: $(tr '\n' ' ' <<< "$snaps")"
    else
        warn "keine Snapshots vorhanden"
    fi

    # Abgestuerzte Session: VM laeuft noch -> zerstoeren
    if [[ "$state" != *"ausgeschaltet"* && "$state" != *"shut off"* ]]; then
        if [[ $CHECK_ONLY -eq 1 ]]; then
            warn "VM laeuft noch - Start wuerde sie zwangsweise beenden"
        else
            warn "VM laeuft aus einer frueheren Session - wird beendet"
            virsh -c "$LIBVIRT_URI" -q destroy "$VM_DOMAIN" >/dev/null 2>&1 \
                && ok "VM beendet" \
                || fail "VM liess sich nicht beenden"
            RESET_VM=1
        fi
    fi

    if [[ $have_snap -eq 0 ]]; then
        if [[ $ALLOW_DIRTY_VM -eq 1 ]]; then
            warn "kein Clean-Snapshot, trotzdem dynamisch (--allow-dirty-vm)"
            hint "Ergebnisse koennen Reste vorheriger Samples enthalten"
        else
            fail "dynamische Analyse ohne Clean-Snapshot blockiert"
            hint "Snapshot anlegen: virsh -c $LIBVIRT_URI snapshot-create-as $VM_DOMAIN clean-state"
            hint "oder bewusst umgehen: --allow-dirty-vm bzw. --static-only"
        fi
        return
    fi

    if [[ $RESET_VM -eq 1 ]]; then
        if [[ $CHECK_ONLY -eq 1 ]]; then
            warn "Start wuerde auf '$VM_SNAPSHOT' zuruecksetzen"
        else
            info "setze VM auf '$VM_SNAPSHOT' zurueck"
            virsh -c "$LIBVIRT_URI" -q snapshot-revert "$VM_DOMAIN" "$VM_SNAPSHOT" >/dev/null 2>&1 \
                && ok "VM auf sauberen Zustand zurueckgesetzt" \
                || fail "snapshot-revert fehlgeschlagen"
        fi
    else
        ok "VM ist aus - RealAnalyzer setzt pro Session selbst zurueck"
    fi
}

check_capture() {
    [[ $STATIC_ONLY -eq 0 ]] || return 0
    section "Netzwerk-Capture"

    local td; td="$(command -v tcpdump || true)"
    if [[ -z "$td" ]]; then
        warn "tcpdump fehlt - kein PCAP-Mitschnitt"
        hint "dnf install tcpdump"
        return
    fi

    local caps; caps="$(getcap "$td" 2>/dev/null || true)"
    if [[ $EUID -eq 0 ]]; then
        ok "laeuft als root - Capture moeglich"
    elif [[ "$caps" == *cap_net_raw* ]]; then
        ok "tcpdump hat cap_net_raw"
    else
        detect_priv
        warn "tcpdump ohne Capabilities - Capture scheitert als normaler Nutzer"
        hint "${PRIV:-sudo} setcap cap_net_raw,cap_net_admin=eip $td"
    fi
}

# --------------------------------------------------------------------------
# 7. Aufraeumen beim Beenden
# --------------------------------------------------------------------------
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ $SHUTDOWN_VM_ON_EXIT -eq 1 && -n "$VM_DOMAIN" && $STATIC_ONLY -eq 0 ]]; then
        if libvirt_reachable; then
            local st; st="$(virsh -c "$LIBVIRT_URI" -q domstate "$VM_DOMAIN" 2>/dev/null || true)"
            if [[ -n "$st" && "$st" != *"ausgeschaltet"* && "$st" != *"shut off"* ]]; then
                printf '\n'
                info "Server beendet - Analyse-VM '$VM_DOMAIN' wird gestoppt"
                virsh -c "$LIBVIRT_URI" -q destroy "$VM_DOMAIN" >/dev/null 2>&1 \
                    && ok "VM gestoppt (Sample laeuft nicht weiter)" \
                    || warn "VM konnte nicht gestoppt werden - bitte pruefen"
            fi
        fi
    fi
    exit "$rc"
}

# --------------------------------------------------------------------------
# Ablauf
# --------------------------------------------------------------------------
printf '%s\n' "$C_B$C_CYN"
cat <<'BANNER'
   _                ___             ___ _
  /_\  _ _ _  _ _ _| _ \_  _ _ _   / __| |___ _ _  ___
 / _ \| ' \ || | '_|   / || | ' \ | (__| / _ \ ' \/ -_)
/_/ \_\_||_\_, |_| |_|_\\_,_|_||_| \___|_\___/_||_\___|
           |__/   REAL Analysis Edition - Malware Sandbox
BANNER
printf '%s' "$C_RST"
printf '%sProjekt: %s%s\n' "$C_DIM" "$PROJECT_DIR" "$C_RST"
[[ $CHECK_ONLY -eq 1 ]] && printf '%sModus:   Preflight only (read-only)%s\n' "$C_DIM" "$C_RST"

check_python
check_dependencies
check_workspace
check_secret
check_ports

if [[ $STATIC_ONLY -eq 1 ]]; then
    section "KVM"
    info "uebersprungen (--static-only): nur statische Analyse"
else
    check_kvm
    check_network
    check_vm_template
    check_vm_state
    check_capture
fi

# --------------------------------------------------------------------------
# Zusammenfassung
# --------------------------------------------------------------------------
section "Zusammenfassung"
printf '  Analyse-Modus : %s\n' "$([[ $STATIC_ONLY -eq 1 ]] && echo 'STATIC (ohne VM-Ausfuehrung)' || echo 'DYNAMIC (KVM-Ausfuehrung aktiv)')"
printf '  Web-UI        : http://%s:%s\n' "$([[ "$HOST" == "0.0.0.0" ]] && echo localhost || echo "$HOST")" "$PORT"
printf '  WebSocket     : ws://%s:%s\n' "$([[ "$HOST" == "0.0.0.0" ]] && echo localhost || echo "$HOST")" "$PORT"
printf '  Bind          : %s\n' "$HOST"
printf '  Debug         : %s\n' "$([[ "$DEBUG" == "1" ]] && echo an || echo aus)"
printf '  Warnungen     : %s / Fehler: %s\n' "$WARNINGS" "$FAILURES"

if [[ "$HOST" == "0.0.0.0" ]]; then
    printf '\n%s  ACHTUNG: UI ist im gesamten Netz erreichbar. Upload von Samples\n'  "$C_YEL"
    printf '  und VNC-Stream sind unauthentifiziert.%s\n' "$C_RST"
fi

if [[ $FAILURES -gt 0 ]]; then
    printf '\n%s%d Fehler - Start abgebrochen.%s\n' "$C_RED$C_B" "$FAILURES" "$C_RST"
    printf '%sStatische Analyse geht meist trotzdem: ./start.sh --static-only%s\n' "$C_DIM" "$C_RST"
    exit 1
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
    printf '\n%sPreflight bestanden - Umgebung ist startklar.%s\n' "$C_GRN$C_B" "$C_RST"
    exit 0
fi

# --------------------------------------------------------------------------
# Start
# --------------------------------------------------------------------------
section "Start"
trap cleanup EXIT INT TERM

export ANYRUN_HOST="$HOST"
export ANYRUN_PORT="$PORT"
export ANYRUN_DEBUG="$DEBUG"
export ANYRUN_STATIC_ONLY="$STATIC_ONLY"
export PYTHONUNBUFFERED=1
[[ -n "${SECRET_KEY:-}" ]] && export SECRET_KEY

info "starte app.py (Beenden mit Strg+C)"
printf '\n'
"$PY" app.py
