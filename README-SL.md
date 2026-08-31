# PowerShell Guardian

Različica 1.1.1 pred zagonom izvede pravi JSON-RPC preizkus konzolnega `PowerShellGuardianBridge.exe`, nato pripravi tunnel-client po uradnem profilnem postopku: `init --force --sample sample_mcp_stdio_local`, `doctor --profile ... --explain` in `run --profile ...`. Tunnel-client bridge zažene neposredno, brez vmesnega PowerShell procesa. Windows pot v profilu uporablja parser-varno obliko s poševnicami naprej, zato presledki v `C:\Program Files\...` ne poškodujejo imena izvršne datoteke. Profil je shranjen pod `ProgramData\PowerShellGuardian\tunnel-client-config`.

PowerShell Guardian je lokalni Zero Trust varnostni prehod med ChatGPT/tunnel-clientom in Windows. ChatGPT ne kliče PowerShella neposredno: vgrajeni MCP bridge vsako zahtevo pošlje lokalnemu gatewayu na `127.0.0.1`, gateway pa preveri bridge skrivnost, aktivno sejo, čas veljavnosti, napravo, whitelist in tveganje.

## Prvi zagon

1. Zaženite `PowerShellGuardian.exe`. Windows zahteva skrbniško potrditev, da ima aplikacija pri vsakem zagonu enak DPAPI in `ProgramData` kontekst.
2. Ob prvem zagonu vnesite tunnel/runtime API ključ. Ključ je zaščiten z Windows DPAPI in ostane shranjen, dokler v programu ne izberete **Change API Key**.
3. Izberite **Change Tunnel ID** in vnesite veljaven ID oblike `tunnel_` + 32 malih šestnajstiških znakov.
4. Izberite **Start System**. Program najprej neposredno zažene `PowerShellGuardianBridge.exe` in preveri njegov MCP `initialize` odgovor. Nato prisilno osveži lastni stdio profil, izvede `doctor --explain` in zažene priloženi `tunnel-client.exe`.

Če zagon ne uspe, odprite `C:\ProgramData\PowerShellGuardian\logs\tunnel-client.log`. Zapis je razdeljen na `PROFILE INIT`, `PROFILE DOCTOR` in dejanski zagon, zato je razvidno, ali gre za napačen ključ/pravice, Tunnel ID, MCP bridge ali zasedena lokalna vrata.

## Seje in odobritve

- Orodje `new_session_request` ustvari lokalno zahtevo s 3-mestno kodo.
- Dokler uporabnik v GUI-ju ne potrdi seje, ni dostopa do ukazov ali datotek.
- Po potrditvi ChatGPT s `session_status` prejme časovno omejen token, vezan na napravo.
- Ukazi v `config/whitelist.json` pod `allowed` se po veljavni seji izvedejo neposredno. Privzeto so to `system_info`, `get_status` in `read_logs`.
- Vsak drug ukaz se ne zavrne: postane HIGH, se prikaže v Pending Command Center in počaka na lokalni **APPROVE** ali **REJECT**.
- `execute_command` sprejme poljuben PowerShell ukaz, vključno z `New-Item`, `Set-Content` in drugimi administrativnimi ukazi. Če ni izrecno dodan v `allowed`, vedno zahteva lokalno potrditev.
- `command_status` vrne rezultat po lokalni odločitvi.

## Odklep samo izbrane seje

V seznamu **Active Sessions** izberite odobreno sejo in kliknite **Unlock / Lock Session**. Samo izbrana seja nato izvaja ukaze brez dodatnega lokalnega potrjevanja in ima v stolpcu **Access** oznako `🔓 Unlocked`. Vse druge seje ohranijo dosedanje obnašanje. Odklep lahko z istim gumbom kadar koli prekličete.

Brisanje datotek vedno zahteva lokalno dovoljenje, tudi v odklenjeni seji. Pravilo velja za orodje `delete` in za zaznane PowerShell ukaze za brisanje. Rekurzivno oziroma imenikovno brisanje ostane blokirano.

Odklenjena seja ima privzeto omejitev največ 5 ustvarjenih datotek v 5 minutah. Ko doseže mejo, so nadaljnji poskusi blokirani do izteka okna. Če seja po izteku okna trikrat zapored znova doseže polno dovoljeno število, se samodejno prekine, v tabeli do izteka seje dobi stanje **TERMINATED: SUSPICIOUS**, v `audit.jsonl` pa se zapišejo število in zaznane poti oziroma imena datotek. Neomejeno oziroma dvoumno paketno ustvarjanje datotek v enem PowerShell ukazu je v odklenjeni seji blokirano.

V **Security Settings** lahko spremenite omejitev datotek, dolžino časovnega okna, število zaporednih polnih oken za prekinitev in vključite ali izključite glavno varovalko za samodejno prekinitev. Osnovna omejitev ustvarjanja datotek ostane vključena.

## Emergency Lock

Rdeči gumb takoj ustavi tunnel, prekine vse seje, zavrne čakajoče ukaze in zaklene gateway. Ponovni **Start System** zahteva lokalno dejanje uporabnika.

## Datoteke

Programske datoteke so pod `Program Files\PowerShellGuardian`. Spremenljivi podatki so pod `ProgramData\PowerShellGuardian`: konfiguracija, DPAPI skrivnosti, seje in audit logi. DPAPI skrivnosti so vezane na Windows uporabnika. Namestitveni program pripravi tudi ročno Windows storitev `PowerShellGuardianGateway`; v headless načinu brez uporabniškega DPAPI konteksta je dostop zaklenjen, zato je za običajno uporabo priporočljiv GUI zagon ob prijavi.

## MCP orodja

`new_session_request`, `session_status`, `system_info`, `get_status`, `read_logs`, `execute_command`, `powershell`, `file_write`, `delete`, `install`, `registry`, `network_change`, `command_status`.

Po spremembi MCP sheme ustavite in ponovno zaženite sistem. Če ChatGPT še vedno prikazuje star seznam orodij, odstranite in ponovno ustvarite priključek, da ponovno prebere `tools/list`.

## Odstranitev

Uninstaller različice 1.1.1 ustavi storitev in celotno procesno drevo aplikacije ter nato izbriše programske datoteke, bližnjice, register in vse lokalne podatke pod `ProgramData\PowerShellGuardian`, `AppData\PowerShellGuardian` in `LocalAppData\PowerShellGuardian`. S tem se trajno izbrišejo tudi API-ključ, Tunnel ID, profili, seje in audit logi. Oddaljeni Tunnel ID v uporabnikovem OpenAI računu ni lokalna datoteka in ga je treba po potrebi ločeno odstraniti v storitvi, kjer je bil ustvarjen.

## Objavljanje na GitHubu

Lastna izvorna koda PowerShell Guardian je vključena pod licenco MIT. Priložena `tunnel-client.exe` in `cloudflared.exe` sta ločeni Apache-2.0 komponenti; njune licence in izvori so navedeni v `THIRD_PARTY_NOTICES.md` in `tunnel/LICENSE`. Nikoli ne objavite vsebine iz `C:\ProgramData\PowerShellGuardian` ali svojih diagnostičnih logov brez pregleda.

## Varnostna opomba

Lokalna potrditev je zadnja varnostna meja. Pred potrditvijo preberite celoten ukaz in pot. API ključ nikoli ni vrnjen MCP odjemalcu in ni zapisan v audit log.
