# app.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import uvicorn

load_dotenv()

from agent.graph import run_agent

app = FastAPI(title="Conversational Threat Intel Agent")

class ChatRequest(BaseModel):
    session_id: str
    message: str

class ChatResponse(BaseModel):
    reply: str
    steps: list   # tool call trace — shown in UI observability panel

@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    result = run_agent(req.session_id, req.message)
    return ChatResponse(reply=result["reply"], steps=result["steps"])

@app.get("/")
async def root():
    return FileResponse("ui/index.html")

app.mount("/static", StaticFiles(directory="ui"), name="static")

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)