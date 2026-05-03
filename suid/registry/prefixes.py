
from enum import Enum

class PREFIX(str, Enum):
    INCIDENT = "INC"
    AUDIT    = "AUD"
    THREAT   = "THR"
    FORENSIC = "FOR"
    ENTITY   = "ENT"
    ALERT    = "ALT"
    SESSION  = "SES"
    def __str__(self): return self.value

PREFIX_LABELS = {
    PREFIX.INCIDENT: "Security Incident",
    PREFIX.AUDIT:    "Audit Entry",
    PREFIX.THREAT:   "Threat Event",
    PREFIX.FORENSIC: "Forensic Record",
    PREFIX.ENTITY:   "Entity",
    PREFIX.ALERT:    "Alert",
    PREFIX.SESSION:  "Session",
}

REGION_COUNTRIES = {
    "KE": "Kenya", "UG": "Uganda", "TZ": "Tanzania",
    "NG": "Nigeria", "ZA": "South Africa", "ET": "Ethiopia",
    "GH": "Ghana",   "RW": "Rwanda",
}

def region_to_country(region_code: str) -> str:
    return REGION_COUNTRIES.get(region_code[:2].upper(), "Unknown")
