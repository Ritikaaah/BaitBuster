from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from api.analyzer import analyze_url
from api.detector import detect_suspicious_features
from api.scorer import calculate_risk_score

#Create our FastAPI application
app = FastAPI(
    title="BaitBuster API",
    description="Backend API for phishing URL detection",
    version="1.0.0"
)

#Define the format of the incoming URL data
class URLRequest(BaseModel):
    url: str

#Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "BaitBuster API is running"
    }

#URL analysis endpoint
@app.post("/analyze")
def analyze(request: URLRequest):

    try:
        # Step 1: Extract URL information
        analysis = analyze_url(request.url)

        # Step 2: Detect suspicious features
        findings = detect_suspicious_features(analysis)

        # Step 3: Calculate risk score
        risk = calculate_risk_score(findings)

        # Step 4: Return all results
        return {
            "analysis": analysis,
            "findings": findings,
            "risk": risk
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )
