#!/bin/bash
# Builds "Android Forensics.app": a desktop application (native window, no Terminal, no browser) that runs from this checkout's .venv.
# usage: build_app.sh [output folder, default ~/Desktop]
set -e
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
OUT="${1:-$HOME/Desktop}"
APP="$OUT/Android Forensics.app"
PY="$REPO/.venv/bin/python"
"$PY" -c "import PySide6" 2>/dev/null || "$REPO/.venv/bin/pip" install -q "PySide6-Essentials>=6.6"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cat > "$APP/Contents/MacOS/AndroidForensics" <<LAUNCH
#!/bin/bash
# Launcher: starts the desktop app from the checkout it was built from.
cd "$REPO"
export ANDROID_FORENSICS_ICON="$(dirname "$0")/../Resources/AppIcon.icns"
exec "$PY" -m android_forensics.gui "\$@"
LAUNCH
chmod +x "$APP/Contents/MacOS/AndroidForensics"
ICONSET="$(mktemp -d)/AppIcon.iconset"
QT_QPA_PLATFORM=offscreen "$PY" packaging/macos/make_icon.py "$ICONSET"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Android Forensics</string>
  <key>CFBundleDisplayName</key><string>Android Forensics</string>
  <key>CFBundleIdentifier</key><string>local.androidforensics.app</string>
  <key>CFBundleExecutable</key><string>AndroidForensics</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.3.0</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --deep -s - "$APP" 2>/dev/null || true
touch "$APP"
echo "Built: $APP"
