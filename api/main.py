from api.analyzer import analyze_url
from api.detector import detect_suspicious_features

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

        print("\n=================================")
        print("Analysis completed.")
        print("=================================")

        print(
            "\nNote: These findings are indicators, "
            "not proof that a website is malicious."
        )

    except ValueError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
