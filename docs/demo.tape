# VHS-Aufnahme für das README-GIF (https://github.com/charmbracelet/vhs)
#
# Nutzt den Demo-Modus: fiktive Hosts im Dokumentationsnetz 192.0.2.0/24 (RFC 5737),
# es werden keine echten Geräte gezeigt und keine Pakete ins reale Netz gesendet.
#
# Aufnahme (netspy muss im PATH liegen):
#   vhs docs/demo.tape
#
# Unter Windows doppelt vhs/ttyd über ConPTY Tastendrücke -> im Linux-Container aufnehmen:
#   GOOS=linux CGO_ENABLED=0 go build -o .vhsbin/netspy
#   MSYS_NO_PATHCONV=1 podman run --rm -v "$(pwd -W):/vhs" -w /vhs \
#     -e PATH="/vhs/.vhsbin:/usr/local/bin:/usr/bin:/bin" ghcr.io/charmbracelet/vhs:v0.10.0 docs/demo.tape
#   rm -rf .vhsbin

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 560
Set Padding 12
Set Theme "Dracula"
Set TypingSpeed 60ms

Type "netspy watch 192.0.2.0/24 --mode demo --interval 5s"
Sleep 500ms
Enter

# Erster Scan + zweiter Scan (neues Gerät erscheint)
Sleep 8s

# Nach Gerätetyp sortieren
Type "d"
Sleep 2s

# Filter: nur Apple-Geräte
Type "/"
Sleep 400ms
Type "apple"
Sleep 400ms
Enter
Sleep 3s

# Filter löschen, nach IP sortieren
Type "c"
Sleep 400ms
Type "i"
Sleep 5s

Type "q"
Sleep 500ms
