from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins="*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"Hello": "World"}


@app.get("/health")
def health_check():
    return {"message": "Hello"}


@app.get("/test")
def test():
    return {"heko": "hh"}


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
