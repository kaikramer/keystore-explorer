#! /bin/bash
set -e

VOLUME_NAME="KeyStore Explorer"

SCRIPT_DIR=$(dirname "$0")

BACKGROUND_IMG="${SCRIPT_DIR}/background.png"
APPLE_SCRIPT="${SCRIPT_DIR}/prepare-dmg.applescript"
KSE_ICNS="${SCRIPT_DIR}/kse.icns"

APP_BUNDLE="$1"

DMG_PATH="$2"
DMG_DIRNAME="$(dirname "$DMG_PATH")"
DMG_DIR="$(cd "$DMG_DIRNAME" > /dev/null; pwd)"
DMG_NAME="$(basename "$DMG_PATH")"
DMG_TEMP_NAME="$DMG_DIR/rw.${DMG_NAME}"

hdiutil create -volname "${VOLUME_NAME}" -ov -fs HFS+ -size 50m "${DMG_TEMP_NAME}"

MOUNT_DIR="/Volumes/${VOLUME_NAME}"
DEV_NAME=$(hdiutil attach -readwrite -noverify -noautoopen "${DMG_TEMP_NAME}" | egrep '^/dev/' | sed 1q | awk '{print $1}')

mkdir "${MOUNT_DIR}/.background"
cp "$BACKGROUND_IMG" "${MOUNT_DIR}/.background/"

cp -a "$APP_BUNDLE" "$MOUNT_DIR"

ln -s /Applications "${MOUNT_DIR}/Applications"

cp "$KSE_ICNS" "${MOUNT_DIR}/.VolumeIcon.icns"
SetFile -c icnC "${MOUNT_DIR}/.VolumeIcon.icns"

"/usr/bin/osascript" "$APPLE_SCRIPT" "$VOLUME_NAME" || true

sleep 4

chmod -Rf go-w "$MOUNT_DIR" &> /dev/null || true
bless --folder "$MOUNT_DIR" --openfolder "$MOUNT_DIR"
SetFile -a C "$MOUNT_DIR"
hdiutil detach "$DEV_NAME"
rm -f "${DMG_DIR}/${DMG_NAME}"
hdiutil convert "$DMG_TEMP_NAME" -format UDZO -imagekey zlib-level=9 -o "${DMG_DIR}/${DMG_NAME}"
rm -f "$DMG_TEMP_NAME"

codesign -s "Kai Kramer" "${DMG_DIR}/${DMG_NAME}"

exit 0