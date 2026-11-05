# Installation Guide

PyAttackMap provides a Python library, a native C++20 scanner, and a browser frontend. The Python package requires Python 3.11 or newer. The native scanner requires CMake 3.20+, Ninja, and a C++20 compiler (GCC 11+, Clang 14+, or Visual Studio 2022). The frontend requires Node.js and npm.

## Install the Python Library

The Python package is not currently published on PyPI. Download the project source from GitHub and install it from the repository root:

```bash
git clone https://github.com/nishit-rane2006/PyAttackMap.git
cd PyAttackMap
python -m pip install .
```

For development, use an editable install with the test dependency:

```bash
python -m pip install -e ".[dev]"
```

Verify the Python package and command-line entry point:

```bash
python -c "import pyattackmap; print(pyattackmap.__version__)"
pyattackmap --help
```

Run the Python test suite:

```bash
python -m pytest legacy_python/tests/ -v
```

## Build the Native C++ Scanner

From the project root:

```bash
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The first CMake configure fetches Tree-sitter, the Tree-sitter Python grammar, nlohmann/json, and GoogleTest, so network access is required.

The CLI is created at `build/release/pyattackmap` (Linux/macOS) or `build/release/pyattackmap.exe` (Windows). To install the executable, library, and headers to a chosen prefix:

```bash
cmake --install build/release --prefix install
```

## Run the Browser Frontend

From the project root:

```bash
cd frontend
npm install
npm run dev
```

Open the local address printed by Vite. To create and preview a production build:

```bash
npm run build
npm run preview
```
