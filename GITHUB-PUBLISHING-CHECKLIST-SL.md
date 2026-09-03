# Pregled pred objavo na GitHubu

Pregledano: 3. september 2026

## Rezultat pregleda

- V izvorni kodi, konfiguracijskih vzorcih, dokumentaciji in testih ni bilo najdenih živih API ključev, session tokenov, Tunnel ID-jev, zasebnih ključev, osebnih e-poštnih naslovov ali uporabniških poti.
- Arhiv ni vseboval `.git`, `.env`, lokalnih dnevnikov, sej, vsebine `ProgramData`, datotek `api.key`, `bridge.key`, `tunnel.id` ali `security.local.json`.
- `config/tunnel.json` je varen vzorec brez Tunnel ID-ja ali API ključa.
- Priložena `tunnel-client.exe` in `cloudflared.exe` sta bajtno enaka komponentama iz pregledane izdaje 1.1.4. Njuni vzorčni Tunnel ID-ji in besedila oblik ključev niso uporabniške skrivnosti.
- Licence MIT in Apache-2.0 ter `THIRD_PARTY_NOTICES.md` so vključene.

## Popravki za javno objavo

- Odstranjeni so bili nedosledni ostanki starega imena iz izvorne kode, MCP opisa, build makra, namespace-a in PE metapodatkov.
- Diagnostika zdaj pravilno prepozna vrstice `[PowerShell Guardian]`.
- Namestitveni program prepreči sočasni zagon predhodno poimenovane storitve in varno preseli staro podatkovno mapo samo, kadar nova še ne obstaja.
- `.gitignore` zdaj dodatno izključuje `.env`, ključe, certifikate, dnevnike, seje, lokalno konfiguracijo in runtime profile.
- `.gitattributes` označi izvršne in slikovne datoteke kot binarne.
- Popravljena je bila ANSI/Unicode napaka pri ListView-u, ki je preprečevala čist strogi build.

## Pred objavo

1. Objavite vsebino vrhnje mape projekta, ne svoje mape `C:\ProgramData\PowerShellGuardian`.
2. Namestitveni EXE je priporočljivo dodati kot GitHub Release artefakt. Veliki tretji binarni komponenti po potrebi hranite v Git LFS ali samo v release artefaktu.
3. Ta build ni digitalno podpisan. Pred javno distribucijo je priporočljiv Authenticode podpis; brez njega lahko Windows prikaže opozorilo SmartScreen.
4. Na Windows 10/11 izvedite še ročni smoke test GUI-ja, UAC-a, DPAPI-ja, lokalnih approval dialogov in dejanskega tunnel zagona.
