#!/usr/bin/env python3
"""
Verify that SARP's XLSX output stores attacker-controlled finding fields as
spreadsheet FORMULA cells (openpyxl data_type 'f'), and that the CSV output
keeps the leading '=' that Excel/LibreOffice read as a formula.

Usage: python verify.py <out.xlsx> <out.csv>
Exit code 0 = injection confirmed, 1 = not confirmed.
"""
import sys
import csv

FORMULA_LEADS = ("=", "+", "-", "@")


def check_xlsx(path):
    import openpyxl
    wb = openpyxl.load_workbook(path)
    ws = wb.active
    formula_cells = []
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            if cell.data_type == "f":
                formula_cells.append((cell.coordinate, cell.value))
    return formula_cells


def check_csv(path):
    hits = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        headers = next(reader, [])
        for r_i, row in enumerate(reader, start=2):
            for c_i, val in enumerate(row):
                if isinstance(val, str) and val[:1] in FORMULA_LEADS:
                    col = headers[c_i] if c_i < len(headers) else f"col{c_i}"
                    hits.append((f"row{r_i}/{col}", val))
    return hits


def main():
    if len(sys.argv) != 3:
        print("usage: python verify.py <out.xlsx> <out.csv>")
        return 2

    xlsx, csv_path = sys.argv[1], sys.argv[2]

    print("== XLSX formula-typed cells (data_type == 'f') ==")
    xlsx_hits = check_xlsx(xlsx)
    for coord, val in xlsx_hits:
        print(f"  {coord}: {val!r}   <-- stored as a live formula")

    print("== CSV cells that begin with a formula lead ==")
    csv_hits = check_csv(csv_path)
    for where, val in csv_hits:
        print(f"  {where}: {val!r}   <-- Excel/LibreOffice evaluate on open")

    if xlsx_hits and csv_hits:
        print("\nRESULT: formula injection CONFIRMED in both XLSX and CSV output.")
        return 0
    print("\nRESULT: not confirmed (no formula cells found).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
