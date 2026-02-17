import json
import sys

from pydantic import ValidationError

from detection.classifiers.heuristics import HeuristicModel
from detection.classifiers.ml import MLModel
from detection.detector import PhishingDetector
from detection.parser import EmailParser
from detection.resolver import HybridMLHeuristicResolver
from models import EmailInput


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/main.py <email_json_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        with open(file_path) as f:
            email_data = json.load(f)

        try:
            email_input = EmailInput(**email_data)
        except ValidationError as e:
            print(f"Error: Invalid email format. {e}")
            sys.exit(1)

        parser = EmailParser()
        heuristics = HeuristicModel()
        ml = MLModel()
        resolver = HybridMLHeuristicResolver()
        detector = PhishingDetector(
            parser=parser, models=[heuristics, ml], resolver=resolver
        )

        result = detector.scan(email_input)

        print(json.dumps(result.model_dump(), indent=2))

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in '{file_path}'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
