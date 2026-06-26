from urllib.parse import urlparse


BLACKLIST_FILE = "blacklist.txt"
SUSPICIOUS_KEYWORDS = ["login", "verify", "bank", "secure", "update"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".click"]


def load_blacklist(filename):
    """Read suspicious domains from a text file."""
    try:
        with open(filename, "r") as file:
            domains = []

            for line in file:
                domain = line.strip().lower()
                if domain:
                    domains.append(domain)

            return domains
    except FileNotFoundError:
        print(f"Warning: Could not find {filename}. Blacklist check skipped.")
        return []


def get_domain(url):
    """Extract the domain from a URL."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urlparse(url)
    return parsed_url.netloc.lower()


def check_url(url, blacklist):
    """Check the URL for phishing signs and return a report."""
    domain = get_domain(url)
    url_lower = url.lower()
    signs_found = []

    if domain in blacklist:
        signs_found.append("Sign A: Domain is found in blacklist.txt")

    if any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS):
        signs_found.append("Sign B: URL contains a suspicious keyword")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        signs_found.append("Sign C: URL uses a suspicious top-level domain")

    return domain, signs_found


def get_risk_level(number_of_signs):
    """Decide risk level based on how many signs were found."""
    if number_of_signs >= 2:
        return "High Risk"
    if number_of_signs == 1:
        return "Medium Risk"
    return "Low Risk"


def main():
    blacklist = load_blacklist(BLACKLIST_FILE)

    user_url = input("Enter a URL to check: ").strip()
    domain, signs_found = check_url(user_url, blacklist)
    risk_level = get_risk_level(len(signs_found))

    print("\n--- Phishing URL Risk Report ---")
    print(f"URL checked: {user_url}")
    print(f"Domain checked: {domain}")
    print(f"Risk level: {risk_level}")
    print(f"Signs triggered: {len(signs_found)}")

    if signs_found:
        for sign in signs_found:
            print(f"- {sign}")
    else:
        print("- No suspicious signs found.")


if __name__ == "__main__":
    main()
