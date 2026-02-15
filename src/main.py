import json
import sys

from detection.classifier import classify_email
from detection.heuristics import analyze_heuristics
from detection.parser import parse_email


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/main.py <email_json_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        with open(file_path) as f:
            email_data = json.load(f)

        parsed = parse_email(email_data)
        if not parsed:
            print("Error: Failed to parse email.")
            sys.exit(1)

        heuristics = analyze_heuristics(parsed)
        classification = classify_email(heuristics)

        print(
            json.dumps(
                {"classification": classification, "heuristics": heuristics}, indent=2
            )
        )

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in '{file_path}'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
