# Bundled fonts

The fonts of the graphical installer and of Strata, SlateOS's desktop.
The installer's ship on the install media only; Strata's are installed
with Strata, when the person chooses it. All are licensed under the SIL Open Font License 1.1; the licence
texts are next to them. None declares a Reserved Font Name.

| File | What | Source |
|---|---|---|
| `HostGrotesk-400.ttf`, `-500`, `-600`, `-800` | Host Grotesk, static instances at those weights | `ofl/hostgrotesk/HostGrotesk[wght].ttf` from google/fonts at commit `0b58fb370093f9a9f4ff785d94405710b79de67c` (sha256 `74c77b8e850d58dd3d8b22e39111a73bef3450de9fb57018ef99119f2d484f5d`) |
| `DMMono-Medium.ttf` | DM Mono Medium, as published (Strata) | `ofl/dmmono/DMMono-Medium.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `fd327daf461db87b44a87def475d251bf03b997f7c07d9680592d75dbbfaad0b`) |
| `DMMono-Regular.ttf` | DM Mono Regular, as published | `ofl/dmmono/DMMono-Regular.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `55b4c98f123daebb3ed27947ba47b2af00554fc6284d639a540bcef5e6258ad2`) |
| `DMMono-Italic.ttf` | DM Mono Italic, as published (the terminal's italics) | `ofl/dmmono/DMMono-Italic.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `32b5bad9cbce64eac6d05c8abbeb619317f7e4cb354e1c33db761adbfaae1b16`) |
| `DMMono-MediumItalic.ttf` | DM Mono Medium Italic, as published (bold italics) | `ofl/dmmono/DMMono-MediumItalic.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `a3b2211bb9cf5c4fc1a0b487553e673a737c2270c59b86bf1e0b48c77e587aa2`) |
| `InstrumentSerif-Italic.ttf` | Instrument Serif Italic, as published (Copper Noir's date) | `ofl/instrumentserif/InstrumentSerif-Italic.ttf` from google/fonts at commit `6157dfaa640ca5738b4d1a7070fe389c3036d7fc` (sha256 `08939b8bdf534afec24ae0ef5e03f948940cd9a8fe08e7fecbad040e62327385`) |
| `Fraunces-600.ttf` | Fraunces 600 at optical size 15 (Sediment's window titles) | `ofl/fraunces/Fraunces[SOFT,WONK,opsz,wght].ttf` from google/fonts at commit `6157dfaa640ca5738b4d1a7070fe389c3036d7fc` (sha256 `177ff6c0f14e5550a3c624247cd1189611d4eb65d000b14944c63d967958abbb`) |
| `Fraunces-Italic-400.ttf` | Fraunces Italic 400 at optical size 14 (Sediment's date) | `ofl/fraunces/Fraunces-Italic[SOFT,WONK,opsz,wght].ttf` from google/fonts at commit `6157dfaa640ca5738b4d1a7070fe389c3036d7fc` (sha256 `b24448c43702fac4ee856781d461a0dfba8d8e594b6e8e190234b75fed2c0e01`) |

Host Grotesk is published only as a variable font; slate-ui reads static
TrueType fonts. The instances were made with fonttools 4.61.1:

```sh
python3 -m fontTools.varLib.instancer 'HostGrotesk[wght].ttf' wght=500 --static \
    --update-name-table -o HostGrotesk-500.ttf
```

Fraunces is published only as variable fonts; the instances were made
the same way, the optical size set to the size each is drawn at:

```sh
python3 -m fontTools.varLib.instancer 'Fraunces[SOFT,WONK,opsz,wght].ttf' \
    opsz=15 wght=600 SOFT=0 WONK=1 --static -o Fraunces-600.ttf
python3 -m fontTools.varLib.instancer 'Fraunces-Italic[SOFT,WONK,opsz,wght].ttf' \
    opsz=14 wght=400 SOFT=0 WONK=1 --static -o Fraunces-Italic-400.ttf
```
