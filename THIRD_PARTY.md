# Fremdpakete und Datenquellen

NetSpy baut auf der Arbeit anderer auf. Diese Datei listet alle Go-Module, die in der
ausgelieferten Binary enthalten sind, sowie die externen Datenquellen und Werkzeuge.
Danke an alle Autorinnen und Autoren!

Stand: NetSpy 0.2.0. Maßgeblich für eine konkrete Version sind `go.mod` / `go.sum` sowie
die SBOM im jeweiligen Release.

## Maschinenlesbare SBOM

Jedes Release enthält pro Plattform eine Software Bill of Materials im
[CycloneDX](https://cyclonedx.org/)-Format (`netspy-<os>-<arch>.cdx.json`), erzeugt mit
[cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod). Die SBOM liegt als
eigenes Release-Asset vor und zusätzlich im ZIP, zusammen mit
`THIRD_PARTY_LICENSES.txt` (vollständige Lizenz- und NOTICE-Texte aller enthaltenen Module).

Lokal erzeugen:

```bash
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
GOOS=linux GOARCH=amd64 cyclonedx-gomod app -json -licenses -assert-licenses -output netspy.cdx.json -main . .
```

## In der Binary enthaltene Module

| Modul | Version | Lizenz | Zweck | Direkt |
|---|---|---|---|---|
| [github.com/rivo/tview](https://github.com/rivo/tview) | v0.42.0 | MIT | Terminal-UI des Watch-Modus | ✓ |
| [github.com/gdamore/tcell/v2](https://github.com/gdamore/tcell) | v2.13.10 | Apache-2.0 | Terminal-Ansteuerung (Basis von tview) | ✓ |
| [github.com/spf13/cobra](https://github.com/spf13/cobra) | v1.10.2 | Apache-2.0 | CLI-Befehle und Shell-Completion | ✓ |
| [github.com/spf13/viper](https://github.com/spf13/viper) | v1.21.0 | MIT | Konfiguration (`~/.netspy.yaml`) | ✓ |
| [github.com/fatih/color](https://github.com/fatih/color) | v1.19.0 | MIT | Farbige CLI-Ausgabe | ✓ |
| [golang.org/x/term](https://cs.opensource.google/go/x/term) | v0.47.0 | BSD-3-Clause | Terminal-Größe und -Modus | ✓ |
| [github.com/gdamore/encoding](https://github.com/gdamore/encoding) | v1.0.1 | Apache-2.0 | Zeichensätze (über tcell) | |
| [github.com/lucasb-eyer/go-colorful](https://github.com/lucasb-eyer/go-colorful) | v1.3.0 | MIT | Farbräume (über tcell) | |
| [github.com/rivo/uniseg](https://github.com/rivo/uniseg) | v0.4.7 | MIT | Unicode-Textbreite (über tview/tcell) | |
| [github.com/mattn/go-colorable](https://github.com/mattn/go-colorable) | v0.1.14 | MIT | ANSI-Farben unter Windows (über color) | |
| [github.com/mattn/go-isatty](https://github.com/mattn/go-isatty) | v0.0.20 | MIT | Terminal-Erkennung (über color) | |
| [github.com/inconshreveable/mousetrap](https://github.com/inconshreveable/mousetrap) | v1.1.0 | Apache-2.0 | Explorer-Start-Erkennung, nur Windows (über cobra) | |
| [github.com/spf13/pflag](https://github.com/spf13/pflag) | v1.0.10 | BSD-3-Clause | POSIX-Flags (über cobra) | |
| [github.com/spf13/afero](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | Dateisystem-Abstraktion (über viper) | |
| [github.com/spf13/cast](https://github.com/spf13/cast) | v1.10.0 | MIT | Typumwandlung (über viper) | |
| [github.com/fsnotify/fsnotify](https://github.com/fsnotify/fsnotify) | v1.9.0 | BSD-3-Clause | Datei-Überwachung (über viper) | |
| [github.com/go-viper/mapstructure/v2](https://github.com/go-viper/mapstructure) | v2.4.0 | MIT | Config-Mapping (über viper) | |
| [github.com/pelletier/go-toml/v2](https://github.com/pelletier/go-toml) | v2.2.4 | MIT | TOML-Parser (über viper) | |
| [go.yaml.in/yaml/v3](https://github.com/yaml/go-yaml) | v3.0.5 | MIT und Apache-2.0 | YAML-Parser (über viper) | |
| [github.com/subosito/gotenv](https://github.com/subosito/gotenv) | v1.6.0 | MIT | `.env`-Parser (über viper) | |
| [github.com/sagikazarmark/locafero](https://github.com/sagikazarmark/locafero) | v0.11.0 | MIT | Config-Dateisuche (über viper) | |
| [github.com/sourcegraph/conc](https://github.com/sourcegraph/conc) | v0.3.1-0.20240121214520-5f936abd7ae8 | MIT | Nebenläufigkeit (über viper) | |
| [golang.org/x/sys](https://cs.opensource.google/go/x/sys) | v0.49.0 | BSD-3-Clause | Systemaufrufe (über color, tcell, term) | |
| [golang.org/x/text](https://cs.opensource.google/go/x/text) | v0.38.0 | BSD-3-Clause | Zeichensatz-Umwandlung (über tcell, viper) | |

Dazu kommt die [Go-Standardbibliothek](https://go.dev/) (BSD-3-Clause).

## Nur für Tests

Diese Pakete werden nicht in die Binary eingebaut.

| Modul | Version | Lizenz | Zweck |
|---|---|---|---|
| [github.com/onsi/ginkgo/v2](https://github.com/onsi/ginkgo) | v2.33.1 | MIT | BDD-Test-Framework |
| [github.com/onsi/gomega](https://github.com/onsi/gomega) | v1.44.0 | MIT | Matcher für Tests |

## Externe Datenquellen

Diese Dienste ruft NetSpy zur Laufzeit ab.

| Quelle | Verwendung | Was gesendet wird |
|---|---|---|
| [IEEE Registration Authority](https://standards.ieee.org/products-programs/regauth/): [MA-L](https://standards-oui.ieee.org/oui/oui.csv), [MA-M](https://standards-oui.ieee.org/oui28/mam.csv), [MA-S](https://standards-oui.ieee.org/oui36/oui36.csv) | Offline-Zuordnung MAC → Hersteller, Cache in `~/.netspy/registry` | Nichts, es werden nur die vollständigen öffentlichen Listen geladen |
| [macvendors.com API](https://macvendors.com/api) | Fallback für Präfixe, die in keiner Registry stehen; Ergebnisse landen in `vendor_learned.txt` | Nur der OUI (die ersten 3 Oktette), nie die vollständige MAC; höchstens 1 Anfrage pro Sekunde |

## Werkzeuge (Build und Doku)

| Werkzeug | Lizenz | Zweck |
|---|---|---|
| [Go](https://go.dev/) | BSD-3-Clause | Compiler und Toolchain |
| [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) | Apache-2.0 | SBOM-Erzeugung im Release |
| [vhs](https://github.com/charmbracelet/vhs) | MIT | Aufnahme von `docs/demo.gif` |
| GitHub Actions: [checkout](https://github.com/actions/checkout), [setup-go](https://github.com/actions/setup-go), [upload-artifact](https://github.com/actions/upload-artifact), [download-artifact](https://github.com/actions/download-artifact), [action-gh-release](https://github.com/softprops/action-gh-release) | MIT | Release-Pipeline |
