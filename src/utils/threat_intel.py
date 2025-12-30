import os
import requests
import json
import functools
import logging
from dotenv import load_dotenv
from typing import Dict, Any, Optional

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class ThreatIntelClient:
    """
    A client for performing IP address threat intelligence lookups using
    AbuseIPDB and VirusTotal APIs.
    """

    def __init__(self):
        """
        Initializes the ThreatIntelClient by loading API keys from environment variables.
        """
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if not self.abuseipdb_api_key:
            logger.warning("ABUSEIPDB_API_KEY not found in environment variables.")
        if not self.virustotal_api_key:
            logger.warning("VIRUSTOTAL_API_KEY not found in environment variables.")

        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        self.virustotal_url = "https://www.virustotal.com/api/v3/ip_addresses/"
    
    @functools.lru_cache(maxsize=128)
    def _get_abuseipdb_report(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Fetches an IP report from AbuseIPDB.

        Args:
            ip_address: The IP address to check.

        Returns:
            A dictionary containing the AbuseIPDB report, or None if an error occurs.
        """
        if not self.abuseipdb_api_key:
            return None

        headers = {
            "Key": self.abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90",  # Reports from the last 90 days
        }

        try:
            response = requests.get(self.abuseipdb_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()
            return data.get("data")
        except requests.exceptions.HTTPError as e:
            logger.error(f"AbuseIPDB HTTP error for {ip_address}: {e.response.status_code} - {e.response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB request error for {ip_address}: {e}")
        except json.JSONDecodeError:
            logger.error(f"AbuseIPDB JSON decode error for {ip_address}: Invalid response")
        return None

    @functools.lru_cache(maxsize=128)
    def _get_virustotal_report(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Fetches an IP report from VirusTotal.

        Args:
            ip_address: The IP address to check.

        Returns:
            A dictionary containing the VirusTotal report, or None if an error occurs.
        """
        if not self.virustotal_api_key:
            return None

        headers = {
            "x-apikey": self.virustotal_api_key,
            "Accept": "application/json",
        }
        url = f"{self.virustotal_url}{ip_address}"

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("data")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.info(f"VirusTotal report not found for {ip_address}.")
            else:
                logger.error(f"VirusTotal HTTP error for {ip_address}: {e.response.status_code} - {e.response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal request error for {ip_address}: {e}")
        except json.JSONDecodeError:
            logger.error(f"VirusTotal JSON decode error for {ip_address}: Invalid response")
        return None

    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Aggregates threat intelligence reports for a given IP address from multiple sources.

        Args:
            ip_address: The IP address to query.

        Returns:
            A dictionary containing aggregated threat intelligence information.
        """
        reputation = {
            "ip_address": ip_address,
            "abuseipdb": {},
            "virustotal": {},
            "summary": "No threat data available.",
            "is_malicious": False,
        }

        abuseipdb_data = self._get_abuseipdb_report(ip_address)
        if abuseipdb_data:
            reputation["abuseipdb"] = {
                "isWhitelisted": abuseipdb_data.get("isWhitelisted"),
                "abuseConfidenceScore": abuseipdb_data.get("abuseConfidenceScore"),
                "countryCode": abuseipdb_data.get("countryCode"),
                "totalReports": abuseipdb_data.get("totalReports"),
            }
            if abuseipdb_data.get("abuseConfidenceScore", 0) > 0 and not abuseipdb_data.get("isWhitelisted"):
                reputation["is_malicious"] = True
                reputation["summary"] = f"AbuseIPDB: Confidence Score {abuseipdb_data['abuseConfidenceScore']}%, {abuseipdb_data['totalReports']} reports."

        virustotal_data = self._get_virustotal_report(ip_address)
        if virustotal_data and virustotal_data.get("attributes"):
            attributes = virustotal_data["attributes"]
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            harmless = last_analysis_stats.get("harmless", 0)
            malicious = last_analysis_stats.get("malicious", 0)
            undetected = last_analysis_stats.get("undetected", 0)
            
            reputation["virustotal"] = {
                "malicious_votes": malicious,
                "harmless_votes": harmless,
                "undetected_votes": undetected,
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
            if malicious > 0:
                reputation["is_malicious"] = True
                vt_summary = f"VirusTotal: {malicious} malicious detections."
                if reputation["summary"] == "No threat data available.":
                    reputation["summary"] = vt_summary
                else:
                    reputation["summary"] += f" {vt_summary}"

        if reputation["is_malicious"] and reputation["summary"] == "No threat data available.":
            reputation["summary"] = "Malicious activity detected, but no specific details from configured sources."
        elif not reputation["is_malicious"] and reputation["summary"] == "No threat data available.":
             reputation["summary"] = "IP address appears clean based on available data."


        return reputation

if __name__ == "__main__":
    # Example usage for testing
    client = ThreatIntelClient()
    
    # Replace with an actual suspicious IP or a known clean one for testing
    test_ip_malicious = "103.20.100.224" # Example malicious IP (check AbuseIPDB for current status)
    test_ip_clean = "8.8.8.8" # Google DNS (should be clean)

    print(f"Checking reputation for {test_ip_malicious}...")
    malicious_reputation = client.get_ip_reputation(test_ip_malicious)
    print(json.dumps(malicious_reputation, indent=2))

    print(f"\nChecking reputation for {test_ip_clean}...")
    clean_reputation = client.get_ip_reputation(test_ip_clean)
    print(json.dumps(clean_reputation, indent=2))
