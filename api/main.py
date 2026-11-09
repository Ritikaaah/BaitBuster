from api.analyzer import analyze_url
from api.detector import detect_suspicious_features
from api.scorer import calculate_risk_score

def main():

    print("=" * 45)
    print("             BAITBUSTER")
    print("       PHISHING LINK CHECKER")
    print("=" * 45)

    url = input("\nEnter a URL to analyze: ")

    try:
        #Analyze the URL
        analysis = analyze_url(url)

        print("\n========== URL ANALYSIS ==========")

        for key, value in analysis.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

        #Detect suspicious characteristics
        findings = detect_suspicious_features(analysis)

        print("\n======= DETECTION RESULTS =======")

        if findings:

            for finding in findings:
                print(f"\n[!] {finding['rule']}")
                print(f"Severity: {finding['severity']}")
                print(f"Reason: {finding['message']}")

        else:
            print("\nNo suspicious characteristics detected.")

        #Calculate the overall risk score
        risk_result = calculate_risk_score(findings)

        print("\n======= RISK ASSESSMENT =======")

        print(f"Risk Score: {risk_result['score']}/100")
        print(f"Risk Category: {risk_result['category']}")

        print(f"\nBaseline Score: {risk_result['baseline']}")
        print(f"Additional Risk Points: {risk_result['points_added']}")

        print("\nSeverity Breakdown:")

        for severity, count in risk_result['breakdown'].items():
            print(f"{severity.title()}: {count}")

        print("\n=================================")
        print("Analysis completed.")
        print("=================================")

        print(
            "\nNote: These findings are indicators, "
            "not proof that a website is malicious."
        )

        print(
            "A low risk score does not guarantee "
            "that a website is safe."
        )

    except ValueError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()