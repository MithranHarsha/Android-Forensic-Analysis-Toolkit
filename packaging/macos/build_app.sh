#!/bin/bash
# Builds "Android Forensics.app": a drop-target app. Drop an evidence folder / .zip / .tar / disk image on it, or double-click to choose one.
set -e
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
OUT="${1:-$HOME/Applications}"
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
	set cmd to "bash " & quoted form of (repoRoot & "/packaging/macos/analyze_evidence.sh") & " " & quoted form of evidencePath & " " & quoted form of repoRoot
	tell application "Terminal"
		activate
		do script cmd
	end tell
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
