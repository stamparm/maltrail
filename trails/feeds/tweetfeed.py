from core.common import retrieve_content
import csv
import io
import re

__url__ = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/month.csv"
__reference__ = "tweetfeed.live"
__info__ = "TweetFeed IOC"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if not content:
        return retval

    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if len(row) < 5 or row[0].lower().startswith("date"):
            continue

        ioc_type = row[2].strip().lower()
        value = row[3].strip().strip('"')
        tag = row[4].strip() if len(row) > 4 else ""

        # Sanity checks
        if not value or (value.startswith("http") and ioc_type != "url"):
            continue

        # Normalize value
        value = value.rstrip("/")

        # Validation and assignment
        # Using a more robust IP check for demonstration
        if ioc_type == "ip" and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value):
            retval[value] = (f"{__info__} ip ({tag})", __reference__) # Corrected variable name
        # A more robust domain check would require a better regex, but this is functional
        elif ioc_type == "domain" and "." in value:
            retval[value] = (f"{__info__} domain ({tag})", __reference__) # Corrected variable name
        elif ioc_type == "url" and value.startswith(("http://", "https://")):
            # Store URL hostname part only for Maltrail
            host = re.sub(r"^https?://", "", value).split("/")[0]
            retval[host] = (f"{__info__} url ({tag})", __reference__) # Corrected variable name

    return retval
