import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from detection.classifiers.heuristics import HeuristicModel
from detection.classifiers.ml import MLModel
from detection.detector import PhishingDetector
from detection.parser import EmailParser
from detection.resolver import HybridMLHeuristicResolver
from logging_config import setup_logging
from models import EmailInput, ScanResult

setup_logging()
logger = logging.getLogger(__name__)

# Global instances (initialized in lifespan)
detector: PhishingDetector = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for model initialization."""
    global detector
    logger.info("Initializing detection system...")

    parser = EmailParser()
    heuristics = HeuristicModel()
    ml_model = MLModel()
    resolver = HybridMLHeuristicResolver()

    detector = PhishingDetector(
        parser=parser, models=[heuristics, ml_model], resolver=resolver
    )

    logger.info("Detection system ready.")
    yield


app = FastAPI(
    title="Email Detection API",
    description="API for detecting phishing emails using heuristics.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.post("/api/v1/analyze", response_model=ScanResult)
async def analyze_email(email: EmailInput):
    """
    Analyze an email for phishing signs.
    """
    try:
        result = detector.scan(email)
        logger.info(
            "Email analyzed: classification=%s, confidence=%.2f",
            result.classification,
            result.confidence_score,
        )
        return result
    except Exception:
        logger.exception("Email analysis failed")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while analyzing the email.",
        ) from None


@app.get("/health")
async def health_check():
    logger.info("Health check")
    return {"status": "healthy"}
