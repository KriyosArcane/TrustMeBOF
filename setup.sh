#!/bin/bash
# TrustMeBOF setup - checks dependencies and builds all BOFs

echo "[*] TrustMeBOF Setup"
echo ""

# Check compiler
if ! command -v x86_64-w64-mingw32-gcc &>/dev/null; then
    echo "[-] Missing: x86_64-w64-mingw32-gcc"
    echo "    Install: sudo apt install gcc-mingw-w64-x86-64"
    exit 1
fi
echo "[+] Compiler: $(x86_64-w64-mingw32-gcc --version | head -1)"

# Build
echo "[*] Building BOFs..."
make clean >/dev/null 2>&1
make
echo ""
echo "[+] Setup complete."
echo ""
echo "Cobalt Strike:"
echo "  Script Manager -> Load -> $(pwd)/cna/tmb.cna"
echo ""
echo "Adaptix C2:"
echo "  Load extension -> $(pwd)/axscript/tmb.axscript"
