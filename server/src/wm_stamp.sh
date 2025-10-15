#!/usr/bin/env bash
# Minimal, portabel stämpling med Ghostscript
# Usage: wm_stamp.sh IN.pdf OUT.pdf "TEXT" [GRAY] [ANGLE] [FONT] [SIZE]

set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 IN.pdf OUT.pdf \"TEXT\" [GRAY] [ANGLE] [FONT] [SIZE]" >&2
  exit 2
fi

IN="$1"
OUT="$2"
TEXT="$3"
GRAY="${4:-0.85}"           # 0=svart, 1=vit
ANGLE="${5:-45}"            # diagonal rotation
FONT="${6:-Helvetica-Bold}" # basfont som alltid finns
SIZE="${7:-48}"

# Escapa för PostScript-sträng
TEXT="${TEXT//\\/\\\\}"
TEXT="${TEXT//\(/\\(}"
TEXT="${TEXT//\)/\\)}"

gs -q -dBATCH -dNOPAUSE -sDEVICE=pdfwrite -sOutputFile="$OUT" \
   -c "/stamptext ($TEXT) def /stampfont /$FONT findfont $SIZE scalefont def \
       /stampgray $GRAY def /stampangle $ANGLE def" \
   -c "<< /EndPage { gsave stampgray setgray stampfont setfont \
       /ps currentpagedevice /PageSize get def \
       ps 0 get 2 div ps 1 get 2 div translate \
       stampangle rotate -200 0 moveto stamptext show grestore true } >> setpagedevice" \
   -f "$IN"
