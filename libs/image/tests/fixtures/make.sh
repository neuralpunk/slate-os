#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The image decoders' test pictures (ADR 0105), made with ImageMagick 7
# from synthetic patterns, each with NAME.rgba beside it: ImageMagick's
# own reading of it as 8-bit RGBA, which the tests compare with ours.
# Run in this directory; the results are committed.
set -e
W=37 H=23
# A colourful picture with a transparent corner, and a photo-like one
# (smooth with detail) for JPEG.
magick -seed 7 -size ${W}x${H} plasma:fractal \
  \( -size ${W}x${H} gradient:white-black -rotate 0 \) -alpha off -compose copy_opacity -composite src-rgba.png
magick -seed 11 -size 61x45 plasma:fractal -blur 0x0.6 src-photo.png

png() { magick src-rgba.png "$@"; }
png -alpha off -colorspace gray -threshold 50% -define png:bit-depth=1 -define png:color-type=0 gray1.png
png -alpha off -colorspace gray -define png:bit-depth=4 -define png:color-type=0 gray4.png
png -alpha off -colorspace gray -define png:bit-depth=8 -define png:color-type=0 gray8.png
png -alpha off -colorspace gray -depth 16 -define png:bit-depth=16 -define png:color-type=0 gray16.png
png -alpha off -depth 8 -define png:bit-depth=8 -define png:color-type=2 rgb8.png
png -alpha off -depth 16 -define png:bit-depth=16 -define png:color-type=2 rgb16.png
png -colors 12 -define png:bit-depth=4 -define png:color-type=3 pal4.png
png -colors 200 -define png:color-type=3 pal8-alpha.png
png -colorspace gray -depth 8 -define png:bit-depth=8 -define png:color-type=4 gray-alpha8.png
png -depth 8 -define png:bit-depth=8 -define png:color-type=6 rgba8.png
png -depth 16 -define png:bit-depth=16 -define png:color-type=6 rgba16.png
png -depth 8 -interlace PNG -define png:bit-depth=8 -define png:color-type=6 rgba8-interlaced.png
png -alpha off -interlace PNG -colors 7 -define png:bit-depth=4 -define png:color-type=3 pal4-interlaced.png

jpg() { magick src-photo.png "$@"; }
jpg -quality 90 -sampling-factor 4:4:4 photo444.jpg
jpg -quality 85 -sampling-factor 4:2:0 photo420.jpg
jpg -quality 85 -sampling-factor 4:2:2 photo422.jpg
jpg -quality 85 -colorspace gray photo-gray.jpg
jpg -quality 80 -sampling-factor 4:2:0 -interlace JPEG photo420-progressive.jpg
jpg -quality 92 -sampling-factor 4:4:4 -interlace JPEG photo444-progressive.jpg
jpg -quality 85 -sampling-factor 4:2:0 -define jpeg:restart-interval=2 photo420-restart.jpg

gif() { magick src-rgba.png "$@"; }
gif -channel A -threshold 50% +channel gif-transparent.gif
gif -alpha off -interlace GIF gif-interlaced.gif

bmp() { magick src-rgba.png "$@"; }
bmp -alpha off -define bmp:format=bmp3 -type truecolor bmp24.bmp
bmp -define bmp:format=bmp4 -type truecoloralpha bmp32.bmp
bmp -alpha off -colors 50 -compress none -define bmp:format=bmp3 -type palette bmp8.bmp
bmp -alpha off -colors 50 -compress rle -define bmp:format=bmp3 -type palette bmp8-rle.bmp
bmp -alpha off -colorspace gray -threshold 50% -define bmp:format=bmp3 -type bilevel bmp1.bmp

for f in *.png *.jpg *.gif *.bmp; do
  case $f in src-*) continue ;; esac
  magick "$f" -depth 8 "rgba:$f.rgba"
done
rm -f src-rgba.png src-photo.png
