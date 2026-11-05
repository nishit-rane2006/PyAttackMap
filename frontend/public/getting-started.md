# PyAttackMap Getting Started

This guide covers native installation, browser setup, and common usage.

## Requirements

For the native C++ scanner:

- CMake 3.20 or newer
- Ninja
- A C++20 compiler: GCC 11+, Clang 14+, or Visual Studio 2022
- Network access during the initial CMake configure to fetch Tree-sitter, the Tree-sitter Python grammar, nlohmann/json, and GoogleTest

For the Python library:

- Python 3.11 or newer
- pip

For the browser frontend, install Node.js and npm.

## Download and install the Python library

The Python library is not currently published on PyPI. [Download the project source as a ZIP](https://github.com/nishit-rane2006/PyAttackMap/archive/refs/heads/main.zip) or clone it, then install from the repository root:

```sh
git clone https://github.com/nishit-rane2006/PyAttackMap.git
cd PyAttackMap
python -m pip install .
```

For development, install the package in editable mode with its pytest dependency:

```sh
python -m pip install -e ".[dev]"
```

Verify the Python package and CLI:

```sh
python -c "import pyattackmap; print(pyattackmap.__version__)"
pyattackmap --help
```

## Build and test the native scanner

Run these commands from the project root:

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The CLI is created at `build/release/pyattackmap` on Linux/macOS or `build\release\pyattackmap.exe` on Windows.

To install the executable, library, and headers to a chosen prefix:

```sh
cmake --install build/release --prefix install
```

Change `install` to another prefix as needed.

## Scan with the CLI

Run a scan on a file or directory:

```sh
# Windows PowerShell
.\build\release\pyattackmap.exe scan .\my_project
.\build\release\pyattackmap.exe scan .\app.py -f json -o report.json

# Linux / macOS
./build/release/pyattackmap scan ./my_project
./build/release/pyattackmap scan ./app.py -f json -o report.json
```

Additional options:

```sh
pyattackmap scan ./my_project -s HIGH -e "tests/*" -e "docs/*"
pyattackmap rules
pyattackmap --help
```

The CLI supports text and JSON reports, severity thresholds (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), repeated exclude patterns, worker thread configuration via `-j`, and `--no-dataflow`.

Exit codes:

- `0`: scan completed with no findings
- `1`: findings detected
- `2`: usage or configuration error
- `3`: execution or file-access error

## Start the browser frontend

From the project root:

```sh
cd frontend
npm install
npm run dev
```

Open the local address printed by Vite. To create and preview a production build:

```sh
npm run build
npm run preview
```

The browser scanner analyzes pasted source or an uploaded Python file. It does not scan project directories.

## Use the C++ library

Link your application with `pyattackmap_lib` and include the public API:

```cpp
#include <iostream>
#include <pyattackmap/pyattackmap.hpp>

int main() {
    auto result = pyattackmap::scan("./src");
    std::cout << result.summary() << "\n";
    result.to_json("report.json");
}
```

The API also provides `pyattackmap::scan_file(...)` and `pyattackmap::scan_code(...)`. Configure scan options with `pyattackmap::ScanConfig`.

## Supported analysis

The native engine currently registers:

- `PAM001`: SQL injection (CWE-89)
- `PAM002`: Command injection (CWE-78)
- `PAM003`: Unsafe deserialization (CWE-502)

The native engine performs intra-procedural static analysis and does not execute target code. The browser frontend is a separate, pattern-based learning tool with 12 detector guides; its coverage differs from the native engine. Static analysis can miss issues or report false positives, so review findings in context.
