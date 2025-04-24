import requests
import os

# URL for CINSSCORE CI-BadGuys feed
CINSSCORE_URL = "https://cinsscore.com/list/ci-badguys.txt"

# Directory where feeds will be stored
DOWNLOAD_DIR = "../../feeds/"

# Ensure the directory exists
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def download_cinsscore_feed(url, download_dir):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Get the filename
            filename = os.path.join(download_dir, "ci-badguys.txt")
            with open(filename, 'w') as f:
                f.write(response.text)
            print(f"Downloaded CINSSCORE feed successfully!")
        else:
            print(f"Failed to download CINSSCORE feed. HTTP Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Request error while downloading CINSSCORE feed: {e}")

download_cinsscore_feed(CINSSCORE_URL, DOWNLOAD_DIR)

# URL for OpenPhish feed
OPENPHISH_URL = "https://openphish.com/feed.txt"

def download_openphish_feed(url, download_dir):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Get the filename
            filename = os.path.join(download_dir, "openphish-feed.txt")
            with open(filename, 'w') as f:
                f.write(response.text)
            print(f"Downloaded OpenPhish feed successfully!")
        else:
            print(f"Failed to download OpenPhish feed. HTTP Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Request error while downloading OpenPhish feed: {e}")

download_openphish_feed(OPENPHISH_URL, DOWNLOAD_DIR)
