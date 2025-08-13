import pandas as pd
from rich.console import Console
from rich.table import Table

def display_data(title: str, data: list[dict]):
    """
    Displays data in a rich table format.
    """
    if not data:
        print(f"No data to display for {title}")
        return

    console = Console()
    table = Table(title=title, show_header=True, header_style="bold magenta")

    # Add columns to the table
    for key in data[0].keys():
        table.add_column(key)

    # Add rows to the table
    for item in data:
        table.add_row(*[str(value) for value in item.values()])

    console.print(table)

def save_to_csv(filename: str, data: list[dict]):
    """
    Saves data to a CSV file.
    """
    if not data:
        print(f"No data to save for {filename}")
        return

    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"Data saved to {filename}")
