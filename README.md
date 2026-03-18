# UBX over UDP Wireshark Plugin

This plugin dissects [UBX protocol](https://www.u-blox.com/en/docs/UBX-18010854) packets carried over UDP port **26423**. It delegates full UBX frame parsing to Wireshark's built-in `ubx` dissector, so all UBX message types (NAV-PVT, NAV-SAT, RXM-RAWX, etc.) are fully decoded.

## Installation

### Windows

1. Get the compiled `ubx-udp.dll` from the latest release, or build it yourself (see below).
2. Find your personal Wireshark plugin folder:
   - Open Wireshark → **Help → About Wireshark → Folders**
   - Look for **Personal Plugins** — typically `%APPDATA%\Wireshark\plugins\x.y\epan\`
3. Copy `ubx-udp.dll` into that folder.
4. Relaunch Wireshark. Verify the plugin loaded under **Help → About Wireshark → Plugins** — look for `ubx-udp`.

### Linux

1. Get the compiled `ubx-udp.so`, or build it yourself (see below).
2. Find your Wireshark plugin folder:
   - Open Wireshark → **Help → About Wireshark → Folders**
   - Look for **Personal Plugins** or **Global Plugins**, e.g. `/usr/lib/x86_64-linux-gnu/wireshark/plugins/x.y/epan/`
3. Copy `ubx-udp.so` into that folder:
   ```sh
   cp ubx-udp.so /usr/lib/x86_64-linux-gnu/wireshark/plugins/4.4/epan/
   ```
4. Relaunch Wireshark and verify under **Help → About Wireshark → Plugins**.

## Compilation

This is an **in-tree** Wireshark plugin. It must be built as part of the Wireshark source tree.

### Prerequisites

- [Wireshark source tree](https://gitlab.com/wireshark/wireshark) checked out
- [Wireshark Windows build environment](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWindows.html) configured
- CMake ≥ 3.12
- Visual Studio 2022 (Windows) or GCC/Clang (Linux)
- Python 3.6+ (required by Wireshark's build system to auto-generate `plugin.c`)

### Steps

#### 1. Copy plugin source into the Wireshark tree

```sh
cp -r ubx-udp-plugin/ <wireshark-source>/plugins/epan/ubx-udp
```

Or on Windows (from the repo root):

```bat
xcopy /E /I ubx-udp-plugin wireshark\plugins\epan\ubx-udp
```

#### 2. Register the plugin with CMake

Edit `<wireshark-source>/CMakeListsCustom.txt` and add the plugin to `CUSTOM_PLUGIN_SRC_DIR`:

```cmake
set(CUSTOM_PLUGIN_SRC_DIR
    plugins/epan/ubx-udp
)
```

#### 3. Configure the build (Windows)

From your build directory (e.g. `wireshark-build/`):

```sh
cmake -G "Visual Studio 17 2022" -A x64 \
    -DPython3_EXECUTABLE="C:/Users/<user>/.pyenv/pyenv-win/versions/3.12.8/python.exe" \
    ../wireshark
```

> If Python is on your `PATH` and not managed by pyenv, you can omit `-DPython3_EXECUTABLE`.

#### 4. Build the plugin

```sh
msbuild /m /p:Configuration=Release plugins\epan\ubx-udp\ubx-udp.vcxproj
```

The compiled DLL will be placed at:

```
wireshark-build\run\Release\plugins\x.y\epan\ubx-udp.dll
```

## Usage

Once installed, any UDP packet on port **26423** will automatically be dissected as UBX. No manual configuration in Wireshark is needed.

- **Display filter**: `ubx_udp` or `udp.port == 26423`
- The protocol tree will show full UBX dissection: preamble (`0xB5 0x62`), message class/ID, payload length, per-message fields, and checksum — identical to what you see for native UBX captures.
