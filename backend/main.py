from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Literal, Optional
import os

from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

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


app = FastAPI(title="Keystone/Capstone Assembler & Disassembler")

# Allow same-origin and local dev frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    """
    Explain what an assembly instruction does in plain language.
    """
    mnemonic_lower = mnemonic.lower()
    ops = [op.strip() for op in op_str.split(",")] if op_str else []
    
    # Common x86 instructions explanations
    explanations = {
        "mov": lambda ops: f"Copy the value from {ops[1] if len(ops) > 1 else 'source'} into {ops[0] if ops else 'destination'}",
        "add": lambda ops: f"Add {ops[1] if len(ops) > 1 else 'value'} to {ops[0] if ops else 'register'} and store the result back in {ops[0] if ops else 'register'}",
        "sub": lambda ops: f"Subtract {ops[1] if len(ops) > 1 else 'value'} from {ops[0] if ops else 'register'} and store the result back in {ops[0] if ops else 'register'}",
        "mul": lambda ops: f"Multiply {ops[0] if ops else 'register'} by the value in AL/AX/EAX/RAX (depending on size) and store result in AL/AX/EAX/RAX",
        "div": lambda ops: f"Divide the value in AL/AX/EAX/RAX by {ops[0] if ops else 'register'} and store quotient in AL/AX/EAX/RAX",
        "inc": lambda ops: f"Increase {ops[0] if ops else 'register'} by 1",
        "dec": lambda ops: f"Decrease {ops[0] if ops else 'register'} by 1",
        "neg": lambda ops: f"Negate (make negative) the value in {ops[0] if ops else 'register'}",
        "not": lambda ops: f"Perform bitwise NOT (flip all bits) on {ops[0] if ops else 'register'}",
        "and": lambda ops: f"Perform bitwise AND between {ops[0] if ops else 'register'} and {ops[1] if len(ops) > 1 else 'value'}, store result in {ops[0] if ops else 'register'}",
        "or": lambda ops: f"Perform bitwise OR between {ops[0] if ops else 'register'} and {ops[1] if len(ops) > 1 else 'value'}, store result in {ops[0] if ops else 'register'}",
        "xor": lambda ops: f"Perform bitwise XOR (exclusive OR) between {ops[0] if ops else 'register'} and {ops[1] if len(ops) > 1 else 'value'}, store result in {ops[0] if ops else 'register'}",
        "shl": lambda ops: f"Shift bits in {ops[0] if ops else 'register'} left by {ops[1] if len(ops) > 1 else 'count'} positions (multiply by 2)",
        "shr": lambda ops: f"Shift bits in {ops[0] if ops else 'register'} right by {ops[1] if len(ops) > 1 else 'count'} positions (divide by 2)",
        "sal": lambda ops: f"Arithmetic shift left (same as SHL) - shift bits in {ops[0] if ops else 'register'} left by {ops[1] if len(ops) > 1 else 'count'}",
        "sar": lambda ops: f"Arithmetic shift right - shift bits in {ops[0] if ops else 'register'} right by {ops[1] if len(ops) > 1 else 'count'} (preserves sign)",
        "rol": lambda ops: f"Rotate bits in {ops[0] if ops else 'register'} left by {ops[1] if len(ops) > 1 else 'count'} positions (wraps around)",
        "ror": lambda ops: f"Rotate bits in {ops[0] if ops else 'register'} right by {ops[1] if len(ops) > 1 else 'count'} positions (wraps around)",
        "push": lambda ops: f"Push {ops[0] if ops else 'value'} onto the stack (decreases stack pointer)",
        "pop": lambda ops: f"Pop a value from the stack into {ops[0] if ops else 'register'} (increases stack pointer)",
        "call": lambda ops: f"Call a function at address {ops[0] if ops else 'address'} (saves return address on stack)",
        "ret": lambda ops: f"Return from function (pops return address from stack and jumps to it)",
        "jmp": lambda ops: f"Jump unconditionally to address {ops[0] if ops else 'address'}",
        "je": lambda ops: f"Jump to {ops[0] if ops else 'address'} if the previous comparison was equal (zero flag set)",
        "jne": lambda ops: f"Jump to {ops[0] if ops else 'address'} if the previous comparison was not equal (zero flag clear)",
        "jz": lambda ops: f"Jump to {ops[0] if ops else 'address'} if zero flag is set (result was zero)",
        "jnz": lambda ops: f"Jump to {ops[0] if ops else 'address'} if zero flag is clear (result was not zero)",
        "jg": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was greater (signed)",
        "jge": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was greater or equal (signed)",
        "jl": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was less (signed)",
        "jle": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was less or equal (signed)",
        "ja": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was above (unsigned)",
        "jae": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was above or equal (unsigned)",
        "jb": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was below (unsigned)",
        "jbe": lambda ops: f"Jump to {ops[0] if ops else 'address'} if previous comparison was below or equal (unsigned)",
        "cmp": lambda ops: f"Compare {ops[0] if ops else 'register'} with {ops[1] if len(ops) > 1 else 'value'} (sets flags without storing result)",
        "test": lambda ops: f"Test {ops[0] if ops else 'register'} by performing bitwise AND with {ops[1] if len(ops) > 1 else 'value'} (sets flags without storing result)",
        "lea": lambda ops: f"Load effective address - calculate address of {ops[1] if len(ops) > 1 else 'memory'} and store it in {ops[0] if ops else 'register'}",
        "nop": lambda ops: "No operation - do nothing (used for padding or delays)",
        "int": lambda ops: f"Trigger interrupt number {ops[0] if ops else '0'} (system call or exception)",
        "syscall": lambda ops: "Make a system call (invoke operating system function)",
        "sysenter": lambda ops: "Fast system call entry (alternative to INT)",
        "leave": lambda ops: "Restore stack frame (equivalent to MOV RSP, RBP; POP RBP)",
        "enter": lambda ops: f"Set up stack frame (allocate {ops[1] if len(ops) > 1 else '0'} bytes of local variables)",
        "pushf": lambda ops: "Push CPU flags register onto the stack",
        "popf": lambda ops: "Pop CPU flags register from the stack",
        "pusha": lambda ops: "Push all general-purpose registers onto the stack",
        "popa": lambda ops: "Pop all general-purpose registers from the stack",
        "xchg": lambda ops: f"Exchange (swap) values between {ops[0] if ops else 'register'} and {ops[1] if len(ops) > 1 else 'register'}",
        "cmpxchg": lambda ops: f"Compare and exchange - compare {ops[0] if ops else 'register'} with AL/AX/EAX/RAX, if equal store {ops[1] if len(ops) > 1 else 'value'} in {ops[0] if ops else 'register'}",
        "lock": lambda ops: "Lock the bus for atomic operation (prefix instruction)",
        "rep": lambda ops: "Repeat next instruction while RCX/ECX/CX > 0 (prefix instruction)",
        "repz": lambda ops: "Repeat next instruction while zero flag set and RCX/ECX/CX > 0",
        "repnz": lambda ops: "Repeat next instruction while zero flag clear and RCX/ECX/CX > 0",
        "stos": lambda ops: f"Store string - store AL/AX/EAX/RAX at address in {ops[0] if ops else 'RDI/EDI/DI'} and update pointer",
        "lods": lambda ops: f"Load string - load from address in {ops[0] if ops else 'RSI/ESI/SI'} into AL/AX/EAX/RAX and update pointer",
        "movs": lambda ops: f"Move string - copy from address in {ops[0] if ops else 'RSI/ESI/SI'} to address in {ops[1] if len(ops) > 1 else 'RDI/EDI/DI'}",
        "scas": lambda ops: f"Scan string - compare AL/AX/EAX/RAX with value at address in {ops[0] if ops else 'RDI/EDI/DI'}",
        "cmps": lambda ops: f"Compare strings - compare values at addresses in {ops[0] if ops else 'RSI/ESI/SI'} and {ops[1] if len(ops) > 1 else 'RDI/EDI/DI'}",
    }
    
    # Try to find explanation
    if mnemonic_lower in explanations:
        try:
            return explanations[mnemonic_lower](ops)
        except:
            pass
    
    # Generic explanation based on instruction type
    if mnemonic_lower.startswith("j"):
        return f"Conditional or unconditional jump to {ops[0] if ops else 'address'}"
    elif mnemonic_lower.startswith("cmov"):
        return f"Conditionally move {ops[1] if len(ops) > 1 else 'value'} to {ops[0] if ops else 'register'} based on flags"
    elif mnemonic_lower.startswith("set"):
        return f"Set {ops[0] if ops else 'register'} to 1 if condition is true, else 0"
    elif mnemonic_lower.startswith("f"):
        return f"Floating-point operation: {mnemonic} {op_str}"
    else:
        return f"Execute {mnemonic} instruction with operands: {op_str if op_str else 'none'}"


def _normalize_register(reg: str, mode: str) -> str:
    """Normalize register names for conversion."""
    reg = reg.lower().strip()
    # Map x86 registers to variable names
    reg_map_64 = {
        "rax": "rax", "rbx": "rbx", "rcx": "rcx", "rdx": "rdx",
        "rsi": "rsi", "rdi": "rdi", "rbp": "rbp", "rsp": "rsp",
        "r8": "r8", "r9": "r9", "r10": "r10", "r11": "r11",
        "r12": "r12", "r13": "r13", "r14": "r14", "r15": "r15",
        "eax": "eax", "ebx": "ebx", "ecx": "ecx", "edx": "edx",
        "esi": "esi", "edi": "edi", "ebp": "ebp", "esp": "esp",
        "al": "al", "bl": "bl", "cl": "cl", "dl": "dl",
        "ah": "ah", "bh": "bh", "ch": "ch", "dh": "dh",
    }
    reg_map_32 = {
        "eax": "eax", "ebx": "ebx", "ecx": "ecx", "edx": "edx",
        "esi": "esi", "edi": "edi", "ebp": "ebp", "esp": "esp",
        "al": "al", "bl": "bl", "cl": "cl", "dl": "dl",
        "ah": "ah", "bh": "bh", "ch": "ch", "dh": "dh",
    }
    reg_map = reg_map_64 if mode == "64" else reg_map_32
    return reg_map.get(reg, reg)


def _parse_operand(op: str, mode: str) -> tuple:
    """Parse an operand and return (type, value, size)."""
    op = op.strip()
    if not op:
        return ("none", "", "")
    
    # Register
    if op.lower() in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                      "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                      "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"]:
        return ("register", op.lower(), "")
    
    # Memory reference [reg] or [reg+offset] or [reg+reg*scale]
    if op.startswith("["):
        return ("memory", op, "")
    
    # Immediate value (hex or decimal)
    if op.startswith("0x") or op.startswith("0X"):
        try:
            val = int(op, 16)
            return ("immediate", str(val), "")
        except:
            return ("immediate", op, "")
    try:
        val = int(op)
        return ("immediate", str(val), "")
    except:
        pass
    
    # Label or symbol
    return ("label", op, "")


@app.post("/api/assemble", response_model=AssembleResponse)
def assemble(req: AssembleRequest) -> AssembleResponse:
    code = req.code.strip()
    if not code:
        raise HTTPException(status_code=400, detail="Assembly code cannot be empty")

    # Basic size guard
    if len(code) > 8000:
        raise HTTPException(status_code=400, detail="Assembly code too long")

    try:
        ks = _get_keystone(req.arch, req.mode)
        encoding, count = ks.asm(code)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Assembly failed: {exc}") from exc

    # Generate explanations for each instruction
    explanations = []
    lines = [line.strip() for line in code.split("\n") if line.strip() and not line.strip().startswith(";")]
    for line in lines:
        # Remove comments
        clean_line = line.split(";")[0].strip()
        if clean_line:
            # Try to parse instruction
            parts = clean_line.split(None, 1)
            if parts:
                mnemonic = parts[0]
                op_str = parts[1] if len(parts) > 1 else ""
                explanations.append(_explain_instruction(mnemonic, op_str))
    
    hex_str = " ".join(f"{b:02x}" for b in encoding)
    return AssembleResponse(bytes=encoding, hex=hex_str, count=count, explanations=explanations if explanations else None)


@app.post("/api/disassemble", response_model=DisassembleResponse)
def disassemble(req: DisassembleRequest) -> DisassembleResponse:
    text = req.hex_bytes.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Hex bytes cannot be empty")

    if len(text) > 8000:
        raise HTTPException(status_code=400, detail="Hex input too long")

    # Normalize and parse hex string into bytes
    try:
        cleaned = text.replace("\n", " ").replace("\r", " ")
        parts = [p for p in cleaned.replace(",", " ").split(" ") if p]
        data = bytes(int(p, 16) for p in parts)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid hex byte format") from exc

    try:
        md = _get_capstone(req.arch, req.mode)
        insns: List[DisassembledInstruction] = []
        base_addr = req.base_address or 0
        for ins in md.disasm(data, base_addr):
            explanation = _explain_instruction(ins.mnemonic, ins.op_str)
            insns.append(
                DisassembledInstruction(
                    address=f"0x{ins.address:x}",
                    mnemonic=ins.mnemonic,
                    op_str=ins.op_str,
                    size=ins.size,
                    explanation=explanation,
                )
            )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Disassembly failed: {exc}") from exc

    return DisassembleResponse(instructions=insns)


@app.get("/")
def index():
    """Serve the frontend page."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    index_path = os.path.join(root, "frontend", "index.html")
    return FileResponse(index_path)

