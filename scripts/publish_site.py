"""Upload the dataset landing page (site/data/index.html) to the R2 bucket root.

The page reads both manifests from the same origin at load time, so it only
needs re-uploading when the page itself changes, not when data is published.
Runs in the dataset-export container, which has the R2 credentials; the HTML
comes in on stdin so a page edit needs no image rebuild:

    docker compose --profile export run --rm -T --build \
        --entrypoint python dataset-export publish_site.py < site/data/index.html

Cloudflare needs a URL rewrite from / to /index.html on the data hostname,
because R2 does not serve index documents.
"""

from __future__ import annotations

import os
import sys

import boto3

KEY = "index.html"


def main() -> None:
    html = sys.stdin.buffer.read()
    if b"<html" not in html[:2048]:
        sys.exit("refusing to upload: stdin does not look like the landing page")
    missing = [k for k in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET")
               if not os.environ.get(k)]
    if missing:
        sys.exit(f"set {', '.join(missing)}")
    s3 = boto3.client(
        "s3",
        endpoint_url=f"https://{os.environ['R2_ACCOUNT_ID']}.r2.cloudflarestorage.com",
        aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
        region_name="auto",
    )
    # Short cache: a page fix should reach readers within minutes.
    s3.put_object(Bucket=os.environ["R2_BUCKET"], Key=KEY, Body=html,
                  ContentType="text/html; charset=utf-8", CacheControl="public, max-age=300")
    print(f"uploaded {KEY} ({len(html)} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
