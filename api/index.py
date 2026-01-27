from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()

@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/api/disassemble")
def disassemble(payload: dict):
    return {"result": "ok"}

handler = Mangum(app)