#!/bin/bash
# Builds "Android Forensics.app": a drop-target app. Drop an evidence folder / .zip / .tar / disk image on it, or double-click to choose one.
set -e
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
OUT="${1:-$HOME/Desktop}"
mkdir -p "$OUT"
SRC="$(mktemp -t afapp).applescript"
cat > "$SRC" <<APPLESCRIPT
property repoRoot : "$REPO"

on run
	set theChoice to button returned of (display dialog "What are you analysing?" buttons {"Cancel", "Disk image / archive file", "Folder"} default button "Folder" with title "Android Forensics")
	if theChoice is "Folder" then
		set picked to choose folder with prompt "Choose the folder containing the extracted Android data"
	else
		set picked to choose file with prompt "Choose a .zip, .tar, .tar.gz, raw/sparse image or .E01"
	end if
	my analyse(POSIX path of picked)
end run

on open droppedItems
	repeat with anItem in droppedItems
		my analyse(POSIX path of anItem)
	end repeat
end open

on analyse(evidencePath)
	set stamp to do shell script "date +%Y%m%d-%H%M%S"
	set baseName to do shell script "basename " & quoted form of evidencePath & " | sed 's/[^A-Za-z0-9._-]/_/g'"
	set caseName to baseName & "-" & stamp
	set logFile to "/tmp/androidforensics-" & caseName & ".log"
	set resultFile to "/tmp/androidforensics-" & caseName & ".result"
	do shell script "nohup bash " & quoted form of (repoRoot & "/packaging/macos/analyze_evidence.sh") & " " & quoted form of evidencePath & " " & quoted form of repoRoot & " " & quoted form of caseName & " " & quoted form of logFile & " " & quoted form of resultFile & " >/dev/null 2>&1 &"
	set progress total steps to -1
	set progress description to "Analysing " & baseName
	set progress additional description to "Starting..."
	repeat
		delay 1.5
		set finished to (do shell script "test -s " & quoted form of resultFile & " && echo yes || echo no")
		if finished is "yes" then exit repeat
		set lastLine to do shell script "tail -n 40 " & quoted form of logFile & " 2>/dev/null | grep -E '[A-Za-z]{3}' | tail -n 1 | cut -c1-90; true"
		if lastLine is not "" then set progress additional description to lastLine
	end repeat
	set resultText to do shell script "cat " & quoted form of resultFile
	set progress total steps to 0
	if resultText is "FAILED" then
		set tailText to do shell script "tail -n 12 " & quoted form of logFile & " 2>/dev/null; true"
		display dialog "The analysis did not complete." & return & return & tailText buttons {"OK"} default button "OK" with icon stop with title "Android Forensics"
	else
		display notification "Report ready: " & baseName with title "Android Forensics" sound name "Glass"
		do shell script "open " & quoted form of resultText
	end if
end analyse
APPLESCRIPT
rm -rf "$OUT/Android Forensics.app"
osacompile -o "$OUT/Android Forensics.app" "$SRC"
# make it accept drops of folders and any file
/usr/libexec/PlistBuddy -c "Delete :CFBundleDocumentTypes" "$OUT/Android Forensics.app/Contents/Info.plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :CFBundleDocumentTypes array" \
  -c "Add :CFBundleDocumentTypes:0 dict" -c "Add :CFBundleDocumentTypes:0:CFBundleTypeName string Evidence" \
  -c "Add :CFBundleDocumentTypes:0:CFBundleTypeRole string Viewer" \
  -c "Add :CFBundleDocumentTypes:0:LSItemContentTypes array" \
  -c "Add :CFBundleDocumentTypes:0:LSItemContentTypes:0 string public.data" \
  -c "Add :CFBundleDocumentTypes:0:LSItemContentTypes:1 string public.folder" \
  "$OUT/Android Forensics.app/Contents/Info.plist"
codesign --force --deep -s - "$OUT/Android Forensics.app" 2>/dev/null
touch "$OUT/Android Forensics.app"
echo "Built: $OUT/Android Forensics.app"
