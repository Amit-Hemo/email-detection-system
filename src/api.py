from fastapi import FastAPI, HTTPException

from detection.classifiers.heuristics import HeuristicModel
from detection.classifiers.ml import MLModel
from detection.detector import PhishingDetector
from detection.parser import EmailParser
from detection.resolver import HybridMLHeuristicResolver
from models import EmailInput, ScanResult

app = FastAPI(
    title="Email Detection API",
    description="API for detecting phishing emails using heuristics.",
    version="1.0.0",
)

parser = EmailParser()
heuristics = HeuristicModel()
ml_model = MLModel()
resolver = HybridMLHeuristicResolver()
detector = PhishingDetector(
    parser=parser, models=[heuristics, ml_model], resolver=resolver
)


@app.post("/api/v1/analyze", response_model=ScanResult)
async def analyze_email(email: EmailInput):
    """
    Analyze an email for phishing signs.
    """
    try:
        result = detector.scan(email)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
