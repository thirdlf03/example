from fastapi import FastAPI
import uvicorn

app = FastAPI()


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
