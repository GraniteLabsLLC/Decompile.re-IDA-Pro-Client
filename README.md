# Decompile.re for IDA Pro

Decompile.re is an AI-assisted reverse-engineering client for IDA Pro. It
analyzes functions and call graphs, applies configured names and types in the
database, supports follow-up questions, and can reconstruct source projects.

## Requirements

- IDA Professional 8.3 through 9.3 with the Hex-Rays decompiler
- IDAPython using Python 3.10 or newer
- A Decompile.re account
- A browser for account sign-in

## Install

Use the
[Decompile.re setup wizard](https://github.com/GraniteLabsLLC/Decompile.re-Setup-Wizard/releases/latest)
to detect IDA installations, install the required Python dependencies, and
install the plugin.

Restart IDA after installation. Decompile.re appears under **Edit > Plugins**
and is available with `Ctrl+Shift+A` or from the disassembly and pseudocode
context menus.

### Manual installation

Manual installation assumes IDAPython is already configured in IDA.

1. Download and extract the plugin ZIP from the
   [latest release](https://github.com/GraniteLabsLLC/Decompile.re-IDA-Pro-Client/releases/latest).
2. Open IDA's Python console and run:

   ```python
   from pathlib import Path
   import idaapi
   import sys

   print("Plugin directory:", Path(idaapi.get_user_idadir()) / "plugins")
   print("Python version:", sys.version)
   print("Python prefix:", sys.prefix)
   ```

3. Create the displayed `plugins` directory if necessary. Copy
   `ida_ai_client.py` and the complete `ida_ai_client` directory from the
   extracted release into it.
4. Use a Python interpreter with the same major and minor version shown by
   IDA to install the release dependencies:

   **Windows PowerShell**

   ```powershell
   & "C:\path\to\matching\python.exe" -m pip install --user -r "C:\path\to\extracted\requirements.txt"
   ```

   **macOS or Linux**

   ```bash
   /path/to/matching/python3 -m pip install --user -r /path/to/extracted/requirements.txt
   ```

5. Remove any older Decompile.re copies from other IDA plugin directories,
   then restart IDA.

If IDAPython or a matching Python installation is unavailable, use the setup
wizard instead of modifying IDA's installation directory manually.

The client checks this repository's stable GitHub Releases feed in the
background. When a newer compatible release is available, an optional
**Update** button appears beside the account control. Restart IDA after an
update.

## Use

1. Open a database and place the cursor in the function you want to analyze.
2. Open Decompile.re and complete browser sign-in.
3. Enter the question or desired outcome.
4. Select an available model mode and start the analysis.
5. Review the report and any proposed database changes.

Source reconstruction writes only beneath the directory selected in IDA.
Before CMake runs, the client asks for approval and warns that generated CMake
configuration can execute local commands.

## Data And Credentials

Analysis sends the user prompt and requested IDA-derived evidence, including
pseudocode, disassembly, strings, symbols, types, and call-graph metadata, to
the Decompile.re service. Do not analyze binaries whose handling policy
prohibits this.

Refresh credentials and the per-device signing key are stored through the
operating system credential store. Access tokens remain in process memory.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

This project is licensed under the
[PolyForm Noncommercial License 1.0.0](LICENSE.md).
