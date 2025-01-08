import base64
import os
import secrets
import string

AUDITD_COMMAND = "-a always,exit -S execve"

BASE64_STRING = "dGVzdAo="

CA_CERT_PATH = os.environ["CA_CERT_PATH"]
CA_KEY_PATH = os.environ["CA_KEY_PATH"]

CLUSTER_TYPE = os.environ["CLUSTER_TYPE"]

DEFAULT_PASSWORD = os.environ["DEFAULT_PASSWORD"]

EXCEPTION_NOT_RIGHT_TYPE = "<ExceptionInfo TypeError('{} parameter is not {}') tblen=2>"

GROUP_OBJECTCLASS = os.environ["GROUP_OBJECTCLASS"]

LDAP_HOST = os.environ["LDAP_HOST"]
LDAP_USERNAME = os.environ["LDAP_USERNAME"]
LDAP_PASSWORD = os.environ["LDAP_PASSWORD"]
LDAP_BASE_DN = os.environ["LDAP_BASE_DN"]

LIST_COUNTRY_NAMES = [
    "Aruba",
    "Afghanistan",
    "Angola",
    "Anguilla",
    "Åland Islands",
    "Albania",
    "Andorra",
    "United Arab Emirates",
    "Argentina",
    "Armenia",
    "American Samoa",
    "Antarctica",
    "French Southern Territories",
    "Antigua and Barbuda",
    "Australia",
    "Austria",
    "Azerbaijan",
    "Burundi",
    "Belgium",
    "Benin",
    "Bonaire, Sint Eustatius and Saba",
    "Burkina Faso",
    "Bangladesh",
    "Bulgaria",
    "Bahrain",
    "Bahamas",
    "Bosnia and Herzegovina",
    "Saint Barthélemy",
    "Belarus",
    "Belize",
    "Bermuda",
    "Bolivia, Plurinational State of",
    "Brazil",
    "Barbados",
    "Brunei Darussalam",
    "Bhutan",
    "Bouvet Island",
    "Botswana",
    "Central African Republic",
    "Canada",
    "Cocos (Keeling) Islands",
    "Switzerland",
    "Chile",
    "China",
    "Côte d'Ivoire",
    "Cameroon",
    "Congo, The Democratic Republic of the",
    "Congo",
    "Cook Islands",
    "Colombia",
    "Comoros",
    "Cabo Verde",
    "Costa Rica",
    "Cuba",
    "Curaçao",
    "Christmas Island",
    "Cayman Islands",
    "Cyprus",
    "Czechia",
    "Germany",
    "Djibouti",
    "Dominica",
    "Denmark",
    "Dominican Republic",
    "Algeria",
    "Ecuador",
    "Egypt",
    "Eritrea",
    "Western Sahara",
    "Spain",
    "Estonia",
    "Ethiopia",
    "Finland",
    "Fiji",
    "Falkland Islands (Malvinas)",
    "France",
    "Faroe Islands",
    "Micronesia, Federated States of",
    "Gabon",
    "United Kingdom",
    "Georgia",
    "Guernsey",
    "Ghana",
    "Gibraltar",
    "Guinea",
    "Guadeloupe",
    "Gambia",
    "Guinea-Bissau",
    "Equatorial Guinea",
    "Greece",
    "Grenada",
    "Greenland",
    "Guatemala",
    "French Guiana",
    "Guam",
    "Guyana",
    "Hong Kong",
    "Heard Island and McDonald Islands",
    "Honduras",
    "Croatia",
    "Haiti",
    "Hungary",
    "Indonesia",
    "Isle of Man",
    "India",
    "British Indian Ocean Territory",
    "Ireland",
    "Iran, Islamic Republic of",
    "Iraq",
    "Iceland",
    "Israel",
    "Italy",
    "Jamaica",
    "Jersey",
    "Jordan",
    "Japan",
    "Kazakhstan",
    "Kenya",
    "Kyrgyzstan",
    "Cambodia",
    "Kiribati",
    "Saint Kitts and Nevis",
    "Korea, Republic of",
    "Kuwait",
    "Lao People's Democratic Republic",
    "Lebanon",
    "Liberia",
    "Libya",
    "Saint Lucia",
    "Liechtenstein",
    "Sri Lanka",
    "Lesotho",
    "Lithuania",
    "Luxembourg",
    "Latvia",
    "Macao",
    "Saint Martin (French part)",
    "Morocco",
    "Monaco",
    "Moldova, Republic of",
    "Madagascar",
    "Maldives",
    "Mexico",
    "Marshall Islands",
    "North Macedonia",
    "Mali",
    "Malta",
    "Myanmar",
    "Montenegro",
    "Mongolia",
    "Northern Mariana Islands",
    "Mozambique",
    "Mauritania",
    "Montserrat",
    "Martinique",
    "Mauritius",
    "Malawi",
    "Malaysia",
    "Mayotte",
    "Namibia",
    "New Caledonia",
    "Niger",
    "Norfolk Island",
    "Nigeria",
    "Nicaragua",
    "Niue",
    "Netherlands",
    "Norway",
    "Nepal",
    "Nauru",
    "New Zealand",
    "Oman",
    "Pakistan",
    "Panama",
    "Pitcairn",
    "Peru",
    "Philippines",
    "Palau",
    "Papua New Guinea",
    "Poland",
    "Puerto Rico",
    "Korea, Democratic People's Republic of",
    "Portugal",
    "Paraguay",
    "Palestine, State of",
    "French Polynesia",
    "Qatar",
    "Réunion",
    "Romania",
    "Russian Federation",
    "Rwanda",
    "Saudi Arabia",
    "Sudan",
    "Senegal",
    "Singapore",
    "South Georgia and the South Sandwich Islands",
    "Saint Helena, Ascension and Tristan da Cunha",
    "Svalbard and Jan Mayen",
    "Solomon Islands",
    "Sierra Leone",
    "El Salvador",
    "San Marino",
    "Somalia",
    "Saint Pierre and Miquelon",
    "Serbia",
    "South Sudan",
    "Sao Tome and Principe",
    "Suriname",
    "Slovakia",
    "Slovenia",
    "Sweden",
    "Eswatini",
    "Sint Maarten (Dutch part)",
    "Seychelles",
    "Syrian Arab Republic",
    "Turks and Caicos Islands",
    "Chad",
    "Togo",
    "Thailand",
    "Tajikistan",
    "Tokelau",
    "Turkmenistan",
    "Timor-Leste",
    "Tonga",
    "Trinidad and Tobago",
    "Tunisia",
    "Türkiye",
    "Tuvalu",
    "Taiwan, Province of China",
    "Tanzania, United Republic of",
    "Uganda",
    "Ukraine",
    "United States Minor Outlying Islands",
    "Uruguay",
    "United States",
    "Uzbekistan",
    "Holy See (Vatican City State)",
    "Saint Vincent and the Grenadines",
    "Venezuela, Bolivarian Republic of",
    "Virgin Islands, British",
    "Virgin Islands, U.S.",
    "Viet Nam",
    "Vanuatu",
    "Wallis and Futuna",
    "Samoa",
    "Yemen",
    "South Africa",
    "Zambia",
    "Zimbabwe",
]
LIST_STATUS_SERVERS_KEYS = ["ldap", "mail", "pki", "session", "sql"]
LIST_STATUS_WEB_TYPES = {
    "webapps": ["OpenID", "PwReset", "SelfDesk", "SelfReg"],
    "websrvs": ["OpenOTP", "SMSHub", "SpanKey"],
}

MSG_AUTH_SUCCESS = "Authentication success"
MSG_ENTER_EMERGENCY_OTP = "Enter your EMERGENCY password"
MSG_INVALID_AUTH_REQUEST = "Invalid authentication request"
MSG_INVALID_OR_NOT_FOUND_USER = "Invalid user or user not found"
MSG_INVALID_PASSWORD = "Invalid password"
MSG_INVALID_REQUEST = "Invalid request"
MSG_INVALID_SMS_REQUEST = "Invalid SMS request"
MSG_INVALID_USERNAME = "Invalid username or password"
MSG_MISSING_SSH_KEY = "Account missing required data or SSH enrollment needed"
MSG_MOBILE_AUTH_CANCELED = "Mobile authentication canceled"
MSG_OPERATION_SUCCESS = "Operation success"
MSG_SERVER_ERROR = "Server error"
MSG_SESSION_ALREADY_STARTED = "Session already started"
MSG_SESSION_NOT_STARTED = "Session not started or timedout"
MSG_SMS_SENT = "SMS send success"
MSG_WELCOME_MESSAGE = "Welcome Message Default"

OPENOTP_API_KEY = os.environ["OPENOTP_API_KEY"]
OPENOTP_TOKENKEY = os.environ["OPENOTP_TOKENKEY"]
OPENOTP_PUSHID = os.environ["OPENOTP_PUSHID"]

with open("tests/test_file.pdf", "rb") as pdf_file:
    PDF_FILE_BASE64 = base64.b64encode(pdf_file.read()).decode("utf-8")

RANDOM_STRING = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(10)
)
RANDOM_CONTEXT = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
)
RANDOM_SESSION = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
)
RANDOM_DATA = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
)
RANDOM_RETRYID = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
)

REGEX_ADDRESS = r"^[0-9a-zA-Zà-üÀ-Ü, -]+$"
REGEX_ASYNC_CONFIRM = (
    r"rcauth:\/\/confirm\/[a-z0-9]*\?version=[0-9]*&timestamp=[a-z0-9]*&reqtime=[0-9]*&session=[a-zA"
    r"-Z0-9]{16}&challenge=[a-z0-9]{32}&signature=[a-z0-9]{32}(&file=[a-z0-9]*){0,1}&client=[a-z0-9]"
    r"{26}&issuer=[a-z0-9]{26}(&flags=ta){0,1}&config=[a-z0-9]{8}"
)
REGEX_ASYNC_SIGN = (
    r"rcauth:\/\/sign\/[a-z0-9]*\?version=[0-9]*&timestamp=[a-z0-9]*&reqtime=[0-9]*&session=[a-zA-Z0-9]"
    r"{16}&challenge=[a-z0-9]{32}&signature=[a-z0-9]{32}(&file=[a-z0-9]*){0,1}&client=[a-z0-9]{26}&issu"
    r"er=[a-z0-9]{26}(&flags=ta){0,1}(&scope=(global|local|eidas)){0,1}&config=[a-z0-9]{8}"
)
REGEX_CONNECTION_REFUSED = (
    r"HTTPSConnectionPool\(host='[^']*', port=[0-9]+\): Max retries exceeded with url: "
    r"/[^/]*/ \(Caused by NewConnectionError\('<urllib3.connection.HTTPSConnection object at "
    r"0x[0-9a-f]{12}>: Failed to establish a new connection: \[Errno 111\] Connection "
    r"refused'\)\)"
)
REGEX_CONNECT_TIMEOUT = (
    r"HTTPSConnectionPool\(host='[^']*', port=[0-9]+\): Max retries exceeded with url: /[^/]*/ \("
    r"Caused by (ConnectTimeoutError)\(<urllib3.connection.HTTPSConnection object at 0x[0-9a-f]{"
    r"12}>, 'Connection to [^ ]* timed out. \(connect timeout=[0-9]+\)'\)\)"
)
REGEX_COORDINATES = r"[0-9\.]*,[0-9\.]*"
REGEX_FAILED_TO_RESOLVE = (
    r"HTTPSConnectionPool\(host='wrong_host', port=[0-9]*\): Max retries exceeded with url: /[^/]*/"
    r" \(Caused by NameResolutionError\(\"<urllib3.connection.HTTPSConnection object at "
    r"0x[0-9a-f]{12}>: Failed to resolve 'wrong_host' "
    r"\(\[Errno -2\] Name or service not known\)\"\)\)"
)
REGEX_IPV4 = (
    r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25["
    r"0-5])$"
)
REGEX_LOGTIME_TIME = r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
REGEX_LOGTIME_SESSION = r"[0-9A-Z]{8}"
REGEX_MAX_RETRY = (
    r"HTTPSConnectionPool\(host='[^']*', port=[0-9]+\): Max retries exceeded with url: /[^/]*/ \("
    r"Caused by NewConnectionError\('<urllib3.connection.HTTPSConnection object at 0x[0-9a-f]{"
    r"12}>: Failed to establish a new connection: \[Errno 113\] No route to host'\)\)"
)
REGEX_PARAMETER_DN_NOT_STRING = (
    "<ExceptionInfo InvalidParams('Parameter dn not String') tblen=3>"
)
REGEX_SESSION_FORMAT = r"^[a-zA-Z0-9]{16,17}$"
REGEX_STATUS_RESPONSE = (
    r"^'Server:.*System:.*Listener:.*Uptime:.*Cluster Node:.*Local Memory:.*Shared Memory:.*"
    r"Connectors:.*'$"
)
REGEX_TIMEOUT = r"[0-9*]"
REGEX_VERSION_NUMBER = r"[0-9.]+"

SETTINGS_LOGINMODE_LDAP = "OpenOTP.LoginMode=LDAP"
SETTING_SPANKEY = "SpanKey.EnableLogin=Yes"

SIGNATURE_DATA = (
    "<![CDATA[<html style='color:white'><b>Sample Confirmation</b><br><br>Account: Example<br>Amount: "
    "XXX.XX Euros<br></html>]]>"
)

SMS_MOBILE = os.environ["SMS_MOBILE"]

SMSHUB_API_KEY = os.environ["SMSHUB_API_KEY"]

SPANKEY_API_KEY = os.environ["SPANKEY_API_KEY"]

SSH_KEY_BACKUP = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCiBDIPHeVWepdhbfppetPJxmPpPygi5is6kpYUziXgCV8tuJTDwVH1c+EO+n3Q"
    "h8nRgODQyiqYegb610nhEJjLzOWDfu0abNxfkJKCnir1OkNIbrmCpCnVxscU/62kg007NLQbc+dASOaOf1tpcEJfgBbsLZEKvJyyGei6OP2DAQic3Y"
    "hXRJ6O0wyTw/TbpEmzDNW8h49t+e9h4iGhwOLcvWuLqkz+5QVvp+URkywvP3FaXRJnDNcDsdhKZLep+VUJ2AXZ9PBZjXRSH5LGkWhWFMTKA"
    "Iu7lIoB7xt6O8ef+lqjIWIc3KldX5bcuDEE3HuJ4Q21YsJum0LHiyZ50/93fXCkdz0/IUd1nYgSneTSa3vZ0l0U4f+LvJK1nThiBiDirB7s"
    "5+1g1fnjqwfIyeHRDGw7OX5p3gFkiS8+V2aRftmcRyJaxJQIHeYac3nxD8NCu1Bg9+TPcjQXP9S0EyiN/b4QP40fOzrSQ3B+3ZZ0e3Odgyf"
    "XAFOGvC2cHS4hG8orrNHNYlhfHkl5CFfiZQhBoAfe7/yrcaUk8MVojmE2nxnHDj9jLQFbeNUkbHM8zf/PuZEmz3sbbD6sEC4oLFYyVw5FfE"
    "bAAu4poGBuNGtwRBknA7qSJQGwrfajJOJBBGxYQ0d4EcfJJ632odwTyxFQ7tuNRIU3EKIGaS9yXL7eDw=="
)

TESTER_NAME = os.environ["TESTER_NAME"]

USER_CERT_PATH = os.environ["USER_CERT_PATH"]

WEBADM_ADMIN_DN = os.environ["WEBADM_ADMIN_DN"]
WEBADM_ADMIN_PASSWORD = os.environ["WEBADM_ADMIN_PASSWORD"]
WEBADM_API_USERNAME = os.environ["WEBADM_API_USERNAME"]
WEBADM_API_PASSWORD = os.environ["WEBADM_API_PASSWORD"]
WEBADM_BASE_DN = os.environ["WEBADM_BASE_DN"]
WEBADM_HOST = os.environ["WEBADM_HOST"]
