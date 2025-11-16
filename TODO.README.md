# TODO Management

## Dateistruktur

### Öffentlich (Git-tracked)
- **`TODO.md`** - Öffentliche Roadmap für GitHub
  - Features, Bugs, Verbesserungen
  - Nichts Internes oder Sensibles
  - Wird committed und gepusht

### Privat (Git-ignored)
- **`TODO.private.md`** - Interne/Private Aufgaben
  - Persönliche Notizen
  - Interne Deadlines
  - Sensible Informationen
  - Client-spezifische Tasks
  - **Wird NICHT committed**

## Verwendung

### Für öffentliche TODOs
```bash
# Bearbeiten
vim TODO.md

# Committen
git add TODO.md
git commit -m "docs: Update public roadmap"
```

### Für private TODOs
```bash
# Bearbeiten
vim TODO.private.md

# Automatisch ignoriert - kein commit nötig
```

## Best Practices

### ✅ In `TODO.md` (öffentlich)
- Feature-Requests
- Bug-Reports
- Architektur-Verbesserungen
- Performance-Optimierungen
- Test-Coverage-Ziele
- Dokumentations-Tasks

### ❌ NICHT in `TODO.md` (öffentlich)
- Interne Deadlines
- Client-Namen
- Kosten/Budget-Informationen
- Persönliche Notizen
- Temporäre Debug-Tasks
- "Quick & Dirty" Lösungen

### ✅ In `TODO.private.md` (privat)
- Alles oben Genannte was NICHT öffentlich sein soll
- Session-Notizen
- Experimente
- Temporäre Aufgaben

## Siehe auch
- `.gitignore` - Enthält Regeln für private TODO-Dateien
- `CONTRIBUTING.md` - Guidelines für Contributors
