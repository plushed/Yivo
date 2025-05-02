import os

# Assuming this file lives in /search/
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # /search/

FEED_PATHS = {
    "openphish": os.path.join(BASE_DIR, "feeds", "openphish-feed.txt"),
    "cins": os.path.join(BASE_DIR, "feeds", "ci-badguys.txt"),
}
