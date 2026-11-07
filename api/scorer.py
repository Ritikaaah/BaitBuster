#Starting score for every URL
BASELINE_SCORE = 5

#Maximum possible risk score
MAX_SCORE = 100

#Points assigned to each severity level
SEVERITY_POINTS = {
    "low": 5,
    "medium": 15,
    "high": 25
}


def calculate_risk_score(findings):
    """
    Calculate the overall risk score based on detected findings.

    Args:
        findings (list): Findings returned by detector.py.

    Returns:
        dict: Risk score, category and scoring breakdown.
    """

    #Start with the baseline score
    total_score = BASELINE_SCORE

    #Keep track of how many findings belong to each severity
    breakdown = {
        "low": 0,
        "medium": 0,
        "high": 0
    }

    #Process every detected finding
    for finding in findings:

        #Make sure every finding is a dictionary
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be a dictionary.")

        #Extract the severity
        severity = finding.get("severity")

        #Make sure severity is valid
        if not isinstance(severity, str):
            raise ValueError("Finding must contain a valid severity.")

        severity = severity.strip().lower()

        if severity not in SEVERITY_POINTS:
            raise ValueError(f"Unknown severity level: {severity}")

        #Add the corresponding points
        points = SEVERITY_POINTS[severity]
        total_score += points

        #Update the severity count
        breakdown[severity] += 1

    #Prevent the score from exceeding 100
    final_score = min(total_score, MAX_SCORE)

    #Determine the risk category
    if final_score >= 60:
        category = "High"

    elif final_score >= 30:
        category = "Medium"

    else:
        category = "Low"

    #Return the scoring results
    return {
        "score": final_score,
        "category": category,
        "baseline": BASELINE_SCORE,
        "points_added": total_score - BASELINE_SCORE,
        "breakdown": breakdown
    }