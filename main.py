import argparse
import logging
import requests
from bs4 import BeautifulSoup
import os
import json
import re
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default Credentials Database (expand as needed)
DEFAULT_CREDENTIALS = {
    "admin": "password",
    "root": "",
    "user": "user",
    "administrator": "admin"
}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-default-credentials-detector: Detects default credentials in web applications.")
    parser.add_argument("url", help="The URL of the target web application.")
    parser.add_argument("-d", "--data", help="Path to a file containing a custom default credentials list (JSON format).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    parser.add_argument("-o", "--output", help="Specify the output file to write results to (JSON format).")
    return parser


def load_custom_credentials(file_path):
    """
    Loads custom default credentials from a JSON file.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: A dictionary containing the custom credentials, or None if an error occurred.
    """
    try:
        with open(file_path, 'r') as f:
            credentials = json.load(f)
            if not isinstance(credentials, dict):
                logging.error("Invalid JSON format.  Expected a dictionary.")
                return None
            return credentials
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in file: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error loading custom credentials: {e}")
        return None

def is_valid_url(url):
    """
    Validates if the given URL is properly formatted.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def check_default_credentials(url, credentials, verbose=False):
    """
    Checks for default credentials on a given URL.

    Args:
        url (str): The URL to check.
        credentials (dict): A dictionary of default usernames and passwords.
        verbose (bool): Enables verbose output.

    Returns:
        list: A list of vulnerabilities found.
    """
    vulnerabilities = []

    try:
        # Implement your default credential checking logic here.
        # This is a placeholder.  You'll need to customize this
        # based on the web application's authentication mechanism.

        # Example:  Assume the app has a login form at /login
        login_url = urljoin(url, "/login")

        for username, password in credentials.items():
            if verbose:
                logging.info(f"Attempting to login with username: {username}, password: {password}")

            # This is a SIMPLIFIED EXAMPLE.  Real-world login mechanisms
            # are often more complex (CSRF tokens, etc.).
            try:
                response = requests.post(login_url, data={"username": username, "password": password}, allow_redirects=False)
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

                # Check for successful login (e.g., redirection or specific content)
                if response.status_code == 302 or "Welcome" in response.text:  # Customize this check
                    vulnerabilities.append({
                        "url": login_url,
                        "username": username,
                        "password": password,
                        "description": f"Default credentials detected: username='{username}', password='{password}'"
                    })
                    logging.warning(f"Default credentials found at {login_url}: username='{username}', password='{password}'")
                    break  # Stop after the first successful login
                else:
                   if verbose:
                       logging.info(f"Login attempt failed with username: {username}")


            except requests.exceptions.RequestException as e:
                logging.error(f"Error during request: {e}")
                continue # Continue to the next credential pair

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    return vulnerabilities


def urljoin(base, path):
    """
    Joins a base URL with a path, handling cases where the base URL
    already ends with a slash or the path starts with a slash.

    Args:
        base (str): The base URL.
        path (str): The path to join.

    Returns:
        str: The joined URL.
    """
    if base.endswith('/'):
        if path.startswith('/'):
            return base[:-1] + path
        else:
            return base + path
    else:
        if path.startswith('/'):
            return base + path
        else:
            return base + '/' + path


def save_results(results, output_file):
    """
    Saves the scan results to a JSON file.

    Args:
        results (list): A list of vulnerabilities found.
        output_file (str): The path to the output file.
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results saved to: {output_file}")
    except Exception as e:
        logging.error(f"Error saving results to file: {e}")

def main():
    """
    Main function to execute the vulnerability scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        return

    # Load custom credentials, if provided
    custom_credentials = {}
    if args.data:
        custom_credentials = load_custom_credentials(args.data)
        if custom_credentials is None:
            return  # Exit if loading custom credentials failed

    # Merge default and custom credentials
    credentials = DEFAULT_CREDENTIALS.copy()
    credentials.update(custom_credentials)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Set log level to DEBUG if verbose is enabled
        logging.debug(f"Target URL: {args.url}")
        logging.debug(f"Credentials being used: {credentials}")

    # Perform vulnerability scan
    vulnerabilities = check_default_credentials(args.url, credentials, args.verbose)

    # Output results
    if vulnerabilities:
        print("Vulnerabilities found:")
        for vuln in vulnerabilities:
            print(f"  - {vuln['description']} at {vuln['url']}")
    else:
        print("No default credential vulnerabilities found.")

    # Save results to file if specified
    if args.output:
        save_results(vulnerabilities, args.output)


if __name__ == "__main__":
    main()