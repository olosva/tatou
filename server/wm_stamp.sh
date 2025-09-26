#!/usr/bin/env bash
# Usage: wm_stamp.sh IN.pdf OUT.pdf "TEXT" [GRAY] [ANGLE] [FONT] [SIZE]
set -euo pipefail

IN="${1:?in.pdf}"
OUT="${2:?out.pdf}"
TEXT="${3:?text}"
GRAY="${4:-0.85}"           # 0=svart, 1=vit
ANGLE="${5:-45}"            # diagonal
FONT="${6:-Helvetica-Bold}" # basfont som alltid funkar
SIZE="${7:-48}"

TEXT="${TEXT//\\/\\\\}"
TEXT="${TEXT//\(/\\(}"
TEXT="${TEXT//\)/\\)}"

gs -q -o "$OUT" -sDEVICE=pdfwrite \
  -c "/stamptext ($TEXT) def /stampfont /$FONT findfont $SIZE scalefont def \
      /stampgray $GRAY def /stampangle $ANGLE def" \
  -c "<< /EndPage { \
        gsave stampgray setgray stampfont setfont \
        /ps currentpagedevice /PageSize get def \
        ps 0 get 2 div ps 1 get 2 div translate \
        stampangle rotate \
        -200 0 moveto stamptext show \
        grestore true } >> setpagedevice" \
  -f "$IN"