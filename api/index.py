from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://assembler-deassembler-mk3lx29zp-vishnu0609s-projects.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/api/disassemble")
def disassemble(payload: dict):
    return {"result": "ok"}

@app.post("/api/assemble")
def assemble(payload: dict):
    return {"result": "ok"}