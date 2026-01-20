## Assembler / Disassembler Website (Keystone × Capstone)

This project is a small web UI that uses the **Keystone** assembler and **Capstone** disassembler
to convert between assembly and machine code.

The backend is written in **Python** using **FastAPI** and exposes JSON APIs that the frontend
consumes via `fetch`.

### Features

- **Assembler (Keystone)**:
  - Input x86 assembly (32-bit or 64-bit).
  - Returns bytes as a hex string and an array of byte values.
- **Disassembler (Capstone)**:
  - Input machine code as hex bytes (spaces, commas and newlines allowed).
  - Returns annotated instructions (address, mnemonic, operands, size).
- Clean, modern single-page UI (no build step required, just static HTML + JS).

### Project Layout

- `backend/main.py` – FastAPI app with `/api/assemble` and `/api/disassemble` endpoints.
- `backend/requirements.txt` – Python dependencies including Keystone and Capstone.
- `frontend/index.html` – Web UI that talks to the backend.

### Prerequisites

- Python 3.9+ installed.
- On Windows, you may need build tools or prebuilt wheels to install `keystone-engine`
  and `capstone`. Refer to their GitHub repositories if pip installation fails:
  - Keystone: `https://github.com/keystone-engine/keystone`
  - Capstone: `https://github.com/capstone-engine/capstone`

### Setup & Run (Windows / PowerShell)

From the project root (`C:\Users\Admin\Desktop\Assembler`):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Then open your browser and visit:

```text
http://localhost:8000/
```

You should see the assembler / disassembler interface.

### API Overview

- **POST** `/api/assemble`

  Request body:

  ```json
  {
    "arch": "x86",
    "mode": "64",
    "code": "mov rax, rbx\nadd rax, 0x10\nret"
  }
  ```

  Response:

  ```json
  {
    "bytes": [72, 137, 216, 72, 131, 192, 16, 195],
    "hex": "48 89 d8 48 83 c0 10 c3",
    "count": 3
  }
  ```

- **POST** `/api/disassemble`

  Request body:

  ```json
  {
    "arch": "x86",
    "mode": "64",
    "hex_bytes": "48 89 d8 48 83 c0 10 c3",
    "base_address": 4096
  }
  ```

  Response:

  ```json
  {
    "instructions": [
      {
        "address": "0x1000",
        "mnemonic": "mov",
        "op_str": "rax, rbx",
        "size": 3
      }
      // ...
    ]
  }
  ```

### Notes

- Currently, only x86 (32-bit and 64-bit) is wired in, but the helpers in `main.py`
  make it straightforward to extend to other architectures and modes supported by
  Keystone and Capstone.
- Error messages from assembly/disassembly are surfaced back to the UI so you can
  see what went wrong.

