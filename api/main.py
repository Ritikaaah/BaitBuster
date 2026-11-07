from api.analyzer import analyze_url

def main():

    print("=" * 45)
    print("       BAITBUSTER - URL ANALYZER")
    print("=" * 45)

    url = input("\nEnter a URL to analyze: ")

    try:
        result = analyze_url(url)

        print("\n========== URL ANALYSIS ==========")

        for key, value in result.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

    except ValueError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
