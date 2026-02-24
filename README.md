# Advanced Hunter Bookmarklet

Advanced Hunter is a bookmarklet and JavaScript tool for Microsoft Defender XDR that injects a modern, draggable, and resizable modal UI for rapid KQL query execution with variable substitution.

## Features
- Loads a query library from an external JSON file ([QueryLibrary.json](docs/QueryLibrary.json))
- Search and filter queries by name
- Displays required and optional key-value pairs (KVPs) for each query
- Substitutes user-provided KVPs into query templates
- Encodes and launches queries directly in Advanced Hunting with correct tenant context
- Modern, accessible, and responsive UI with dark theme

## Usage
1. Host `docs/AdvancedHunter.js` and `docs/QueryLibrary.json` on GitHub Pages or any web server.
2. Use the loader bookmarklet in [AdvancedHunterBookmarklet.txt](AdvancedHunterBookmarklet.txt) to inject the script into Microsoft Defender XDR.
3. Enter KVPs (one per line, e.g., `alertid=...`).
4. Search and select a query from the library.
5. Click **Submit** to open the query in Advanced Hunting.

## Adding New Queries
Edit `docs/QueryLibrary.json`. Each query requires:
- `name`: Display name
- `requiredKvps`: Array of required KVP keys (lowercase)
- `optionalKvps`: (optional) Array of optional KVP keys
- `template`: KQL query with `{{key}}` placeholders

## Security
The bookmarklet performs an integrity check on the script before injection. If the hash does not match, the script will not run.

## Files
- `docs/AdvancedHunter.js`: Main JavaScript UI and logic
- `docs/QueryLibrary.json`: Query library (editable)
- `AdvancedHunterBookmarklet.txt`: Loader bookmarklet for injection

---

**Author:** Suhail Rahmetulla
