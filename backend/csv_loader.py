import csv
from io import StringIO
from pathlib import Path
from typing import Any

import pandas as pd


MAX_NETWORK_SAMPLE_ROWS = 100
GROUND_TRUTH_COLUMNS = {"Label", "ClassLabel"}
NETWORK_FLOW_FEATURE_COLUMNS = {
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "SYN Flag Count",
    "Packet Length Mean",
}
DEFAULT_CSV_PATH = Path(__file__).resolve().parent / "data" / "threatforge_sample.csv"


def _network_flow_dataset(
    frame: pd.DataFrame,
    row_count: int,
    random_state: int,
) -> dict[str, Any]:
    frame = frame.copy()
    frame.columns = [str(column).strip() for column in frame.columns]
    removed_columns = [
        column
        for column in frame.columns
        if column.casefold() in {name.casefold() for name in GROUND_TRUTH_COLUMNS}
    ]
    labels_removed = sorted({
        next(name for name in GROUND_TRUTH_COLUMNS if name.casefold() == column.casefold())
        for column in removed_columns
    })

    if frame.empty:
        return {
            "records": [],
            "row_count": 0,
            "feature_count": 0,
            "feature_columns": [],
            "missing_value_count": int(frame.isna().sum().sum()),
            "missing_by_column": {
                str(column): int(frame[column].isna().sum())
                for column in frame.columns
            },
            "labels_removed": labels_removed,
        }

    sanitized = frame.drop(columns=removed_columns).drop_duplicates()
    if sanitized.empty:
        raise ValueError("Network-flow CSV contains no feature records")

    feature_columns = [str(column) for column in sanitized.columns]
    selected = sanitized.sample(
        n=min(row_count, len(sanitized)),
        random_state=random_state,
    )
    selected = selected.replace([float("inf"), float("-inf")], pd.NA)

    records: list[dict[str, Any]] = []
    for _, row in selected.iterrows():
        record: dict[str, Any] = {}
        for column in sanitized.columns:
            value = row[column]
            if pd.isna(value):
                record[str(column)] = None
            elif isinstance(value, pd.Timestamp):
                record[str(column)] = value.isoformat()
            else:
                record[str(column)] = value.item() if hasattr(value, "item") else value
        records.append(record)

    return {
        "records": records,
        "row_count": len(records),
        "feature_count": len(feature_columns),
        "feature_columns": feature_columns,
        "missing_value_count": int(selected.isna().sum().sum()),
        "missing_by_column": {
            str(column): int(selected[column].isna().sum())
            for column in selected.columns
        },
        "labels_removed": labels_removed,
    }


def parse_network_flow_csv_text(content: str) -> dict[str, Any] | None:
    if not content.strip():
        return None

    header_line = content.lstrip("\ufeff \t\r\n").splitlines()[0]
    try:
        headers = next(csv.reader([header_line]))
    except csv.Error:
        return None
    normalized_headers = {header.strip().casefold() for header in headers}
    if not normalized_headers.intersection(
        column.casefold() for column in NETWORK_FLOW_FEATURE_COLUMNS
    ):
        return None

    try:
        frame = pd.read_csv(StringIO(content))
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid network-flow CSV: {exc}") from exc

    if frame.empty:
        raise ValueError("Network-flow CSV contains no data records")
    if len(frame) > MAX_NETWORK_SAMPLE_ROWS:
        raise ValueError(
            f"Network-flow CSV cannot exceed {MAX_NETWORK_SAMPLE_ROWS} records"
        )

    return _network_flow_dataset(frame, row_count=len(frame), random_state=0)


def load_network_flow_sample(
    row_count: int = 100,
    csv_path: str | Path = DEFAULT_CSV_PATH,
    random_state: int = 20241121,
) -> dict[str, Any]:
    if row_count < 1:
        raise ValueError("network_sample_size must be at least 1")
    if row_count > MAX_NETWORK_SAMPLE_ROWS:
        raise ValueError(
            f"network_sample_size cannot exceed {MAX_NETWORK_SAMPLE_ROWS}"
        )

    path = Path(csv_path)
    if not path.is_file():
        raise FileNotFoundError(f"Network-flow CSV not found: {path}")
    if path.suffix.lower() != ".csv":
        raise ValueError("Network-flow source must be a CSV file")

    try:
        frame = pd.read_csv(path)
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid network-flow CSV: {exc}") from exc

    return _network_flow_dataset(frame, row_count, random_state)
