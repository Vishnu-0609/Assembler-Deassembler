from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Literal, Optional

from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


# =====================
# Request / Response Models
# =====================

class AssembleRequest(BaseModel):
    arch: Literal["x86"] = "x86"
    mode: Literal["32", "64"] = "64"
    code: str


class DisassembleRequest(BaseModel):
    arch: Literal["x86"] = "x86"
    mode: Literal["32", "64"] = "64"
    hex_bytes: str
    base_address: Optional[int] = 0x1000


class AssembleResponse(BaseModel):
    bytes: List[int]
    hex: str
    count: int
    explanations: Optional[List[str]] = None


class DisassembledInstruction(BaseModel):
    address: str
    mnemonic: str
    op_str: str
    size: int
    explanation: str


class DisassembleResponse(BaseModel):
    instructions: List[DisassembledInstruction]


# =====================
# App Init
# =====================

app = FastAPI(title="Keystone/Capstone Assembler & Disassembler")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://assembler-deassembler.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================
# Helpers
# =====================

def _get_keystone(arch: str, mode: str) -> Ks:
    if arch == "x86":
        if mode == "32":
            return Ks(KS_ARCH_X86, KS_MODE_32)
        if mode == "64":
            return Ks(KS_ARCH_X86, KS_MODE_64)
    raise HTTPException(status_code=400, detail="Unsupported arch/mode combination")


def _get_capstone(arch: str, mode: str) -> Cs:
    if arch == "x86":
        if mode == "32":
            return Cs(CS_ARCH_X86, CS_MODE_32)
        if mode == "64":
            return Cs(CS_ARCH_X86, CS_MODE_64)
    raise HTTPException(status_code=400, detail="Unsupported arch/mode combination")


def _explain_instruction(mnemonic: str, op_str: str) -> str:
    mnemonic_lower = mnemonic.lower()
    ops = [o.strip() for o in op_str.split(",")] if op_str else []

    explanations = {
        "mov": lambda o: f"Copy value from {o[1]} into {o[0]}",
        "add": lambda o: f"Add {o[1]} to {o[0]}",
        "sub": lambda o: f"Subtract {o[1]} from {o[0]}",
        "cmp": lambda o: f"Compare {o[0]} with {o[1]}",
        "jmp": lambda o: f"Jump to {o[0]}",
        "call": lambda o: f"Call function at {o[0]}",
        "ret": lambda o: "Return from function",
        "push": lambda o: f"Push {o[0]} onto stack",
        "pop": lambda o: f"Pop value into {o[0]}",
        "nop": lambda o: "No operation",
    }

    if mnemonic_lower in explanations and len(ops) >= 1:
        try:
            return explanations[mnemonic_lower](ops)
        except:
            pass

    return f"Execute {mnemonic} {op_str}".strip()


# =====================
# Routes
# =====================

@app.get("/")
def health():
    return {"status": "ok", "service": "assembler-disassembler"}


@app.post("/api/assemble", response_model=AssembleResponse)
def assemble(req: AssembleRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Assembly code cannot be empty")

    try:
        ks = _get_keystone(req.arch, req.mode)
        encoding, count = ks.asm(req.code)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Assembly failed: {exc}")

    hex_str = " ".join(f"{b:02x}" for b in encoding)

    explanations = []
    for line in req.code.splitlines():
        line = line.split(";")[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        explanations.append(
            _explain_instruction(parts[0], parts[1] if len(parts) > 1 else "")
        )

    return AssembleResponse(
        bytes=encoding,
        hex=hex_str,
        count=count,
        explanations=explanations or None,
    )


@app.post("/api/disassemble", response_model=DisassembleResponse)
def disassemble(req: DisassembleRequest):
    try:
        data = bytes(int(b, 16) for b in req.hex_bytes.replace(",", " ").split())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex byte format")

    md = _get_capstone(req.arch, req.mode)
    insns = []

    for ins in md.disasm(data, req.base_address or 0):
        insns.append(
            DisassembledInstruction(
                address=f"0x{ins.address:x}",
                mnemonic=ins.mnemonic,
                op_str=ins.op_str,
                size=ins.size,
                explanation=_explain_instruction(ins.mnemonic, ins.op_str),
            )
        )

    return DisassembleResponse(instructions=insns)