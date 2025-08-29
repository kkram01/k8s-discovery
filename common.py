import datetime
import json
import logging
import os


def json_serial(obj):
    """JSON serializer for objects not serializable by default, like datetime."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def save_to_json(data, output_file):
    """Saves data to a JSON file."""
    if not data:
        logging.info("No data found to save for %s.", output_file)
        return

    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, default=json_serial)
    logging.info("Successfully wrote data to %s", output_file)
