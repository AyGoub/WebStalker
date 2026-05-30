# WebStalker

Outil de reconnaissance passive et active pour la sécurité offensive.

## Modules

| Module | Description |
|---|---|
| **Passive** | WHOIS, DNS enumeration, subdomain discovery |
| **Active** | Port scan (nmap), HTTP headers, tech detection |
| **Fuzzing** | Directory/file brute-force, sensitive file finder |
| **Report** | Rapport JSON + TXT sauvegardé automatiquement dans `output/` |

---

## Installation

```bash
git clone https://github.com/AyGoub/WebStalker.git
cd WebStalker
pip install -r requirements.txt
```

> nmap doit être installé sur le système pour le port scan :
> ```bash
> sudo apt install nmap
> ```

---

## Usage

```bash
# Tout lancer (passive + active + fuzzing)
python3 recon.py <domain>

# Passive uniquement
python3 recon.py <domain> --passive

# Active uniquement
python3 recon.py <domain> --active

# Fuzzing uniquement
python3 recon.py <domain> --fuzz
```

---

## Options

### Passive
```bash
--whois             WHOIS lookup
--dns               DNS enumeration
--dns --types A MX  DNS avec types spécifiques
--subdomains        Subdomain enum (HackerTarget + AlienVault OTX)
```

### Active
```bash
--ports             Port scan nmap (1-1000 par défaut)
--port-range 1-65535  Port range custom
--headers           Analyse des headers HTTP
--tech              Détection CMS / Framework / WAF / CDN
```

### Fuzzing
```bash
--dirfuzz                         Brute-force de répertoires/fichiers
--dirfuzz --ext php bak html      Avec extensions
--dirfuzz --wordlist /path/to/wl  Wordlist custom
--sensitive                       Recherche de fichiers sensibles (.env, .git, backups...)
--threads 30                      Nombre de threads (défaut: 20)
--codes 200 403                   Filtrer par code HTTP
```

### Output
```bash
--no-report         Ne pas générer de rapport
```

---

## Exemples

```bash
# Scan complet
python3 recon.py tesla.com

# Seulement WHOIS + DNS
python3 recon.py tesla.com --whois --dns

# Port scan sur toute la plage
python3 recon.py tesla.com --ports --port-range 1-65535

# Fuzzing avec filtre 200 uniquement
python3 recon.py tesla.com --dirfuzz --codes 200

# Fichiers sensibles uniquement
python3 recon.py tesla.com --sensitive
```

---

## Structure

```
WebStalker/
├── recon.py              # Point d'entrée CLI
├── requirements.txt
├── modules/
│   ├── passive.py        # WHOIS, DNS, subdomains
│   ├── active.py         # Port scan, headers, tech detection
│   ├── fuzzing.py        # Dir fuzzer, sensitive finder
│   └── report.py         # Génération de rapports
├── wordlists/
│   └── sensitive.txt     # Fichiers sensibles à tester
└── output/               # Rapports générés (gitignored)
```

---

## Sources de données

| Source | Usage | Clé API |
|---|---|---|
| HackerTarget | Subdomain enum | Non |
| AlienVault OTX | Subdomain enum (passive DNS) | Non |
| nmap | Port scan | Non |

---

> **Avertissement** : Cet outil est destiné à des tests de sécurité autorisés uniquement.  
> Ne pas utiliser sur des systèmes sans autorisation explicite.
