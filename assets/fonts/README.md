# Bundled fonts

The fonts of the graphical installer and of Strata, SlateOS's desktop.
The installer's ship on the install media only; Strata's are installed
with Strata, when the person chooses it. Both are licensed under the SIL Open Font License 1.1; the licence
texts are next to them. Neither declares a Reserved Font Name.

| File | What | Source |
|---|---|---|
| `HostGrotesk-400.ttf`, `-500`, `-600`, `-800` | Host Grotesk, static instances at those weights | `ofl/hostgrotesk/HostGrotesk[wght].ttf` from google/fonts at commit `0b58fb370093f9a9f4ff785d94405710b79de67c` (sha256 `74c77b8e850d58dd3d8b22e39111a73bef3450de9fb57018ef99119f2d484f5d`) |
| `DMMono-Medium.ttf` | DM Mono Medium, as published (Strata) | `ofl/dmmono/DMMono-Medium.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `fd327daf461db87b44a87def475d251bf03b997f7c07d9680592d75dbbfaad0b`) |
| `DMMono-Regular.ttf` | DM Mono Regular, as published | `ofl/dmmono/DMMono-Regular.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `55b4c98f123daebb3ed27947ba47b2af00554fc6284d639a540bcef5e6258ad2`) |
| `DMMono-Italic.ttf` | DM Mono Italic, as published (the terminal's italics) | `ofl/dmmono/DMMono-Italic.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `32b5bad9cbce64eac6d05c8abbeb619317f7e4cb354e1c33db761adbfaae1b16`) |
| `DMMono-MediumItalic.ttf` | DM Mono Medium Italic, as published (bold italics) | `ofl/dmmono/DMMono-MediumItalic.ttf` from google/fonts at commit `bfb7c046dea572dca9fdd435481ba2f36b0a1ebc` (sha256 `a3b2211bb9cf5c4fc1a0b487553e673a737c2270c59b86bf1e0b48c77e587aa2`) |

Host Grotesk is published only as a variable font; slate-ui reads static
TrueType fonts. The instances were made with fonttools 4.61.1:

```sh
python3 -m fontTools.varLib.instancer 'HostGrotesk[wght].ttf' wght=500 --static \
    --update-name-table -o HostGrotesk-500.ttf
```
