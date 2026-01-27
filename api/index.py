from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()

@app.get("/")
def root():
    return {"status": "Assembler API running on Vercel"}

@app.post("/api/disassemble")
def disassemble(payload: dict):
    code = payload.get("code", "")
    return {
        "input": code,
        "output": "fake-disassembly-for-now"
    }

# 🔥 This is REQUIRED for Vercel
handler = Mangum(app)