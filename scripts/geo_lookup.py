"""
geo_lookup.py

Resolves an IPv4 address to (asn, asn_name, country) using two pinned
DB-IP Lite CSV snapshots (CC BY 4.0, https://db-ip.com):
  - ASN-lite:     range_start,range_end,asn,asn_name
  - Country-lite: range_start,range_end,country_code

Both are range-based, one row per IP range, with range_start and
range_end as plain dotted-quad IPv4 addresses (not CIDR notation).
Each is loaded into its own sorted table and binary-searched
independently via bisect, since the two files don't share range
boundaries — an IP can land in different-sized ranges in each.

DB-IP uses "ZZ" as a placeholder country code for unallocated/reserved
ranges; we treat that as no match rather than a real country.
"""

import csv
import bisect
import ipaddress
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

UNKNOWN_COUNTRY_CODE = "ZZ"


@dataclass
class GeoResult:
    ip: str
    asn: Optional[str]
    asn_name: Optional[str]
    country: Optional[str]
    matched: bool  # True if ASN matched (primary signal); country may still be None


class GeoLookup:
    def __init__(self, asn_csv_path: str, country_csv_path: str):
        self.asn_csv_path = Path(asn_csv_path)
        self.country_csv_path = Path(country_csv_path)

        if not self.asn_csv_path.exists():
            raise FileNotFoundError(
                f"DB-IP ASN-lite CSV not found at {asn_csv_path}. "
                f"Download it per data/geo/SOURCE.md before running this script."
            )
        if not self.country_csv_path.exists():
            raise FileNotFoundError(
                f"DB-IP Country-lite CSV not found at {country_csv_path}. "
                f"Download it per data/geo/SOURCE.md before running this script."
            )

        self._asn_starts: list[int] = []
        self._asn_rows: list[tuple] = []  # (start_int, end_int, asn, asn_name)

        self._country_starts: list[int] = []
        self._country_rows: list[tuple] = []  # (start_int, end_int, country_code)

        self._load_asn()
        self._load_country()

    def _load_asn(self):
        with open(self.asn_csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue

                if len(row) < 4:
                    continue

                start_raw, end_raw, asn_raw, asn_name = row[0], row[1], row[2], row[3]

                try:
                    start_int = int(ipaddress.IPv4Address(start_raw))
                    end_int = int(ipaddress.IPv4Address(end_raw))
                except ipaddress.AddressValueError:
                    continue

                asn = f"AS{asn_raw}" if asn_raw else None
                self._asn_rows.append((start_int, end_int, asn, asn_name))

        self._asn_rows.sort(key=lambda r: r[0])
        self._asn_starts = [r[0] for r in self._asn_rows]

    def _load_country(self):
        with open(self.country_csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue

                # DB-IP Country-lite columns: range_start, range_end, country_code
                if len(row) < 3:
                    continue

                start_raw, end_raw, country_code = row[0], row[1], row[2]

                try:
                    start_int = int(ipaddress.IPv4Address(start_raw))
                    end_int = int(ipaddress.IPv4Address(end_raw))
                except ipaddress.AddressValueError:
                    continue

                self._country_rows.append((start_int, end_int, country_code))

        self._country_rows.sort(key=lambda r: r[0])
        self._country_starts = [r[0] for r in self._country_rows]

    def _lookup_asn(self, ip_int: int) -> tuple[Optional[str], Optional[str], bool]:
        idx = bisect.bisect_right(self._asn_starts, ip_int) - 1
        if idx < 0:
            return None, None, False

        start_int, end_int, asn, asn_name = self._asn_rows[idx]
        if start_int <= ip_int <= end_int:
            return asn, asn_name, True

        return None, None, False

    def _lookup_country(self, ip_int: int) -> Optional[str]:
        idx = bisect.bisect_right(self._country_starts, ip_int) - 1
        if idx < 0:
            return None

        start_int, end_int, country_code = self._country_rows[idx]
        if start_int <= ip_int <= end_int:
            if country_code == UNKNOWN_COUNTRY_CODE:
                return None
            return country_code

        return None

    def lookup(self, ip: str) -> GeoResult:
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError:
            return GeoResult(ip=ip, asn=None, asn_name=None, country=None, matched=False)

        asn, asn_name, asn_matched = self._lookup_asn(ip_int)
        country = self._lookup_country(ip_int)

        return GeoResult(
            ip=ip,
            asn=asn,
            asn_name=asn_name,
            country=country,
            matched=asn_matched,
        )


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("usage: python geo_lookup.py <asn_csv> <country_csv> <ip> [ip ...]")
        sys.exit(1)

    geo = GeoLookup(sys.argv[1], sys.argv[2])
    for ip in sys.argv[3:]:
        result = geo.lookup(ip)
        print(result)
