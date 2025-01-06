import base64
import os
import secrets
import string

AUDITD_COMMAND = "-a always,exit -S execve"

BASE64_STRING = "dGVzdAo="

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

CLUSTER_TYPE = os.environ["CLUSTER_TYPE"]

WEBADM_ADMIN_DN = os.environ["WEBADM_ADMIN_DN"]
WEBADM_ADMIN_PASSWORD = os.environ["WEBADM_ADMIN_PASSWORD"]
WEBADM_API_USERNAME = os.environ["WEBADM_API_USERNAME"]
WEBADM_API_PASSWORD = os.environ["WEBADM_API_PASSWORD"]
WEBADM_BASE_DN = os.environ["WEBADM_BASE_DN"]
WEBADM_HOST = os.environ["WEBADM_HOST"]

USER_CERTIFICATES = {
    "normal": "-----BEGIN CERTIFICATE-----\n"
    "MIIHBjCCBO6gAwIBAgIRAJ2SnlftBR5aTIieJDL3VoAwDQYJKoZIhvcNAQELBQAw\n"
    "fTEZMBcGA1UECAwQRXNjaC1zdXItQWx6ZXR0ZTELMAkGA1UECwwCSVQxEzARBgNV\n"
    "BAoMClRFU1RXRUJBRE0xGTAXBgNVBAcMEEVzY2gtc3VyLUFsemV0dGUxFjAUBgNV\n"
    "BAMMDVRFU1RXRUJBRE0gQ0ExCzAJBgNVBAYTAkxVMB4XDTI1MDEwMzEwMTM0MFoX\n"
    "DTI2MDEwMzEwMTM0MFowgbMxJjAkBgNVBAMMHURvbWFpbl9FbmFibGVkXHVfbm9y\n"
    "bWFsX2FwaV8xMR4wHAYKCZImiZPyLGQBAQwOdV9ub3JtYWxfYXBpXzExHjAcBgoJ\n"
    "kiaJk/IsZAEZFg5Eb21haW5fRW5hYmxlZDEXMBUGA1UECgwOUkNEZXZzIFN1cHBv\n"
    "cnQxFzAVBgNVBGEMDlZBVExVLTAwMDAwMDAwMRcwFQYDVQQEDA51X25vcm1hbF9h\n"
    "cGlfMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK5rpJVJRM8oHGO3\n"
    "Vps1zR7tWgH7QVKGwPUOw6ywUsDawqhpx9ITJj9X6pXHlVTr+ITy7Aew2tEkEmB1\n"
    "orNTZ+9qUyHRQaeMAf94ZlxQt2imSn7QPJWJcsr3UgvqEGMFvy+ANTOu655uZQ1y\n"
    "ntzl9GbcYe2akan8gW0N3w30KljEyeWHwKrOt5bJRqdSG5AUnqVQqpEk1RiVW4DW\n"
    "79H6+V+s9sTvRxsdv2taf3YslQL9plIw6ufiRyASe4avaHnkc1KvkYAp23uPfINF\n"
    "WrPdDIBS1JWi5P1yTYp2H+0jRvZk4GGGJ6RSEYew5PDhFycNnA52dB1SG96RrpE5\n"
    "wVHqdMHGYQFYKYS22bPkAvWbe0gA+mwlAEX91hHPHe1l2amykYxvZW0ijbltWxGI\n"
    "tVcwFcA31bMxDjp5SBGQQrBqMt3qMxs/o5gvGZCkO4JFGX6x0NufqfbOmpRCRQck\n"
    "oDGgb7ZSgVpiI4t1bDHXrceyp2PN1zK1Wzv03c0vKoMI+lorbqq2JT9Eogkh+YpI\n"
    "od6ZqmKn+YVgVivrU7pvwXgAx2ELtUa1MYA+q6ZOp+6YZJXmugi6PRq0DYjHe6w5\n"
    "0op+Nj4mkreNYHhnvRYd38T59DK/V+ZUPDJWlcvxEYoyF7eSRU/LNuRAtaRHvNvx\n"
    "GBlix+DHhW7dLfm7gV0MsAFQxEfXAgMBAAGjggFIMIIBRDALBgNVHQ8EBAMCBeAw\n"
    "KQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3FAICMB0GA1Ud\n"
    "DgQWBBTxwz3wuVaCB9zZYm8vT3BzMZGEYjCBlQYIKwYBBQUHAQEEgYgwgYUwRwYI\n"
    "KwYBBQUHMAKGO2h0dHA6Ly9jbG91ZC5yY2RldnMuY29tL2NhL3FncjZtb2pibWts\n"
    "Z28vY2FjZXJ0Lz9mb3JtYXQ9ZGVyMDoGCCsGAQUFBzABhi5odHRwOi8vY2xvdWQu\n"
    "cmNkZXZzLmNvbS9jYS9xZ3I2bW9qYm1rbGdvL29jc3AvMD4GA1UdHwQ3MDUwM6Ax\n"
    "oC+GLWh0dHA6Ly9jbG91ZC5yY2RldnMuY29tL2NhL3FncjZtb2pibWtsZ28vY3Js\n"
    "LzATBgsrBgEEAYKOOQMBAQQEVVNFUjANBgkqhkiG9w0BAQsFAAOCAgEAA4uC7Awn\n"
    "lUyC8V8aSlz71kHQWmusutXutaE7xN2uCtepFufjfHmgSUWjG0ce3+VtG3zXI59j\n"
    "glV8+91hra96sPrVF+EdgZRkl+z2iPxCrAcH+yypj8/xyzH78nPuik0oNfB5kxCY\n"
    "0jmjx8e8FV8Yh9YnXv47u6/PLE2NkpUEodfKDQ55Y5P3IaP8Y+qPyKEZDbnh7Wl3\n"
    "LrEsv7s0/W/VnggnZ7fvsURJq80SJuZgeTWhlIGxOhjzB+wV2ba/T6rK6EmQIqYD\n"
    "CbjYEPvtEXG38XyKe5GKAlqZz193GBQl4S2O9ShgbUCmIuWlD4jPMyzImSrXBnlC\n"
    "ByVRaVCckw3wR2mwmXdddDRi4ENMiUnSDJ3NuWvb6DuHPQ+2+unG1i8mEd3HUmzG\n"
    "QeCZHozs4GShFiVTBJZu5K2B8trj2evBks7fBZmSbOnTMyqiDIUY1GL61CYGlp4X\n"
    "RyuaWwXg0+pS3tIZ/0g+UUhy983W/yldfzl+KQ8vUyFzHbXON9Pmrkmx7EOj9ECR\n"
    "ZHeZOASCSOZhG9KfIJ8kNemYzbvAVuohRKMIivQw8D+iQzAOl7c4hcbwuwUVz48c\n"
    "Ob6aLCH+DaJRokJj8mjS+jU+Lmw7etMo0AG9GPuL+m9/CVcNJzqFkg3UzxuGJnqr\n"
    "uFhCgBRer0EelolplfbMfNOL0jrvWGjmx3I=\n"
    "-----END CERTIFICATE-----",
    "metadata": "-----BEGIN CERTIFICATE-----\n"
    "MIIHDDCCBPSgAwIBAgIRAPIKr8c1Zi7wiD9iAGhI3dUwDQYJKoZIhvcNAQELBQAw\n"
    "fTEZMBcGA1UECAwQRXNjaC1zdXItQWx6ZXR0ZTELMAkGA1UECwwCSVQxEzARBgNV\n"
    "BAoMClRFU1RXRUJBRE0xGTAXBgNVBAcMEEVzY2gtc3VyLUFsemV0dGUxFjAUBgNV\n"
    "BAMMDVRFU1RXRUJBRE0gQ0ExCzAJBgNVBAYTAkxVMB4XDTI1MDEwMzA4MTUwOFoX\n"
    "DTI2MDEwMzA4MTUwOFowgbkxKDAmBgNVBAMMH0RvbWFpbl9FbmFibGVkXHVfbWV0\n"
    "YWRhdGFfYXBpXzExIDAeBgoJkiaJk/IsZAEBDBB1X21ldGFkYXRhX2FwaV8xMR4w\n"
    "HAYKCZImiZPyLGQBGRYORG9tYWluX0VuYWJsZWQxFzAVBgNVBAoMDlJDRGV2cyBT\n"
    "dXBwb3J0MRcwFQYDVQRhDA5WQVRMVS0wMDAwMDAwMDEZMBcGA1UEBAwQdV9tZXRh\n"
    "ZGF0YV9hcGlfMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALhA+8Bz\n"
    "vZwW54M2fFC7bJHHL6hqJnMPkmDxkxzieL0Kgt+fy/B4YEqsBHTEScJ9WP1thaa/\n"
    "MLbbnqW3oi2yCOF+IGjWCGEr4oBPMxXLI2uPq7WDMhP3VQYt4AY0rACkN1wSHpMM\n"
    "R0XeRQBQvxVmDcnTnPXu4YkjUJaPzMiKDza47f9teNH9l+Ec7jiW8NfHaNb/BHvk\n"
    "3Sr52XvA9NrKGOi4HTiZAxWjH9P/PZbZJ6Ny9IC5ChhIrPDcfkrwkDk/U3ApiYEc\n"
    "V+tyrFnrsNLGc+1pETL2LpraEgDW5J1ArNaG39OjZ5h0gzZOWlVaTwIaIInikiRq\n"
    "+JI+MeClAJZGHpP6VMj2XiOdL4AkCEP1KKTRhbioAvIHMNVOTokrzU5Nt2ggEkgN\n"
    "b+fY7cwXRrsm6401z7aDvzAWy/dRN36s/D2UO9MhvUnLfQi8CTRHagBCV7iSH5k7\n"
    "nk7JjfH3eTeJ2KjGUDV3WbB1jOo8T1o7JlRHH7EspOuvUbupHQeZ25FWBpmt1KYv\n"
    "5H+2PM00Z5OfTt0gL2P+Fwcq3Oo4V35+g55IthXdlMS+TEaMeThyciwrx/tiVEs5\n"
    "SaYDMJV+OaFWtjvM7kUY46HcWS71zcjVKhv122uNlYSY4+js2McP2jeEoE2FVq15\n"
    "VkxGiipOYBUOT+w2KMrOFfEFxS18ZRqZCemJAgMBAAGjggFIMIIBRDALBgNVHQ8E\n"
    "BAMCBeAwKQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3FAIC\n"
    "MB0GA1UdDgQWBBQl6mvswBZfSuoBG0sUzW4ObDVOhjCBlQYIKwYBBQUHAQEEgYgw\n"
    "gYUwRwYIKwYBBQUHMAKGO2h0dHA6Ly9jbG91ZC5yY2RldnMuY29tL2NhL2ttNTdp\n"
    "Z2xqbWdibWsvY2FjZXJ0Lz9mb3JtYXQ9ZGVyMDoGCCsGAQUFBzABhi5odHRwOi8v\n"
    "Y2xvdWQucmNkZXZzLmNvbS9jYS9rbTU3aWdsam1nYm1rL29jc3AvMD4GA1UdHwQ3\n"
    "MDUwM6AxoC+GLWh0dHA6Ly9jbG91ZC5yY2RldnMuY29tL2NhL2ttNTdpZ2xqbWdi\n"
    "bWsvY3JsLzATBgsrBgEEAYKOOQMBAQQEVVNFUjANBgkqhkiG9w0BAQsFAAOCAgEA\n"
    "uF2SuZIvCwr/w7i3v3+Aj7i9l6VBxG1ZHCz2JRUOILh3JWxyPidedyyUg3rhi+Zn\n"
    "EAWrdNe1sU36uamqecw1WAZHzFC8ewBI6S8TrBT9OYCYgzN4gOaQ+BuY/8JtiFe0\n"
    "n425IwwLf18MdF8Bv0retiDGmzUwAXnjKZwSEwuChY4Otk77gTQO3uDC7CUROnZy\n"
    "X7K8gFAYUeRnogats94sQx4B1Dr38VXIHfFri7KGj9Rim6a9PbSb144xCc7AeAGE\n"
    "ZTlJSMptAi/4FCO+u4aIJl7oYNSDBpnJEC4iu/ev9GKri4A/YDR2Jt5ciN4IWKlr\n"
    "cocp+eJhCMMkcVXBua8N+er6iYQixUhQAOXl6j2PV0fwenV3xP2MVdcP4kZmeGDy\n"
    "DloRi7rvCIBG+bIKVAPkyZ6MhMXRIV7rwZ/hZI/20hJ25EcJPkJ/vGpelYIS+2B1\n"
    "U9iGlzVoRM9nj75ILtgQt+mq0483p/LV5x6jxU+OF8MpfdYkz+nnNvxTo0DxLmUg\n"
    "BLMzlv/lMH0Gh7p0G/GGk61fQAXJeQCuTXzDwusIPaRKMwtL7iIxx2JZR7GDHsit\n"
    "Qgn1cV8ajatEIJyzoJnMSK93JdWzGHSprhe7nDu075XIaUTxTw84gN1/ownhfWrD\n"
    "lYeNLFOzYIeR/57m0YINRsca1jGWaBxJG4R70geEb/U=\n"
    "-----END CERTIFICATE-----",
    "mssp": "-----BEGIN CERTIFICATE-----\n"
    "MIIGuDCCBKCgAwIBAgIRAJmB4TvQLpK89+vcQcyamC4wDQYJKoZIhvcNAQELBQAw\n"
    "fTEZMBcGA1UECAwQRXNjaC1zdXItQWx6ZXR0ZTELMAkGA1UECwwCSVQxEzARBgNV\n"
    "BAoMClRFU1RXRUJBRE0xGTAXBgNVBAcMEEVzY2gtc3VyLUFsemV0dGUxFjAUBgNV\n"
    "BAMMDVRFU1RXRUJBRE0gQ0ExCzAJBgNVBAYTAkxVMB4XDTI1MDEwMzExNDI1NFoX\n"
    "DTI2MDEwMzExNDI1NFowgY8xJDAiBgNVBAMMG0RvbWFpbl9FbmFibGVkXHVfbXNz\n"
    "cF9hcGlfMTEcMBoGCgmSJomT8ixkAQEMDHVfbXNzcF9hcGlfMTEeMBwGCgmSJomT\n"
    "8ixkARkWDkRvbWFpbl9FbmFibGVkMRIwEAYDVQQuEwljdXN0b21lckExFTATBgNV\n"
    "BAQMDHVfbXNzcF9hcGlfMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\n"
    "AL4lpKuo+YfX5IfHxTI3UTbJjGIuZRHCHdfBCmls37BkkWeAbkRmPSYZpan+VPS9\n"
    "t9sYtrSg6QUTn/6ZdSDKGAIF4kA5MqoO+A9DycTOpQA0J3qyt5MWCyAGkvBVRn6/\n"
    "pzLlZOilHrSaTY/L5b6BtJbtbnYxwBPNCcAMWtgrAy0jmdTaZWU6qr31pscOzoGR\n"
    "Bo3u54U6Mc0o1FxuDFnoyY+Qb79xOuND/eyIlP3uv3cjNo65P+y6J+c39dNsHEsi\n"
    "3x2prKzq3+h8qadiY2bX1PhvTixqxuiaoJeCTA+hEvXADB2j+rlXX85m7Hm+vzXz\n"
    "ybEwKLxL0fn3JdHqtWI+R6gLXPKkuIw91dhpUuQEY9e3LUWh0+6kgAoCuLB11dZz\n"
    "4aczh/jl5kmW46u3FswDDY6oxZCVa88tr9fnufbMglfPUtH6jIFgQWkNxl6kTpH9\n"
    "KsNxbycsqtd6w/G5w+1w2CzhrcLIjxZ57lxtNwppfsha/x+JnXHRbDlkHopaoddA\n"
    "vwob1c5dGXySL9zV/JR6WriFPjQS8mh0U/qUJ5b/A0W8siob0udC+nebn4HMEXh/\n"
    "CgTJGmyEOsKbUZ3fWoqYfNkdaAJq0RL0fsKwz0QA/yfM7Hz6a2Wce3AAYlCea80G\n"
    "HeogxvBDELzQCxsTE3T+FhOJlhZdm/IwFO1gEnIVwmjhAgMBAAGjggEeMIIBGjAL\n"
    "BgNVHQ8EBAMCBeAwKQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEE\n"
    "AYI3FAICMB0GA1UdDgQWBBQHaqr4VXD6M1/oi7+uGwnPZlvNMDB5BggrBgEFBQcB\n"
    "AQRtMGswOgYIKwYBBQUHMAKGLmEud2ViYWRtLW1zc3AudGVzdGluZy5sb2NhbC9j\n"
    "YWNlcnQvP2Zvcm1hdD1kZXIwLQYIKwYBBQUHMAGGIWEud2ViYWRtLW1zc3AudGVz\n"
    "dGluZy5sb2NhbC9vY3NwLzAxBgNVHR8EKjAoMCagJKAihiBhLndlYmFkbS1tc3Nw\n"
    "LnRlc3RpbmcubG9jYWwvY3JsLzATBgsrBgEEAYKOOQMBAQQEVVNFUjANBgkqhkiG\n"
    "9w0BAQsFAAOCAgEAOHZpfuOPjcZlv92PC25XJbHpMi8p6lc3dm7oCV5cdeRmZPvI\n"
    "BPQbMvi8iFc1CmI0WgXKWjY9m1HC+MeAzj7d8izWw4TbE57TD9V6lty9GHiSUloh\n"
    "mMDnKcspe1Z+xcpFP+wY2OFg99PLyo7w83HDVJeX0OABgw8vQSdHM1MVxWkq0BzD\n"
    "f6xseza9nN43MqPRF4OKs5U8fxv1C/AajmQXbziEyXZ4VIhqaPqvA780yDb3t9vT\n"
    "imZ0eTy4I4xaiQIvLJM4otLg4cThFh0JvWKhJgH0n+LRuHpq6xIqu7lm3KXBVycs\n"
    "2LqVhdedOQp4PbdIwcQmr/g1pgJ/ijOByzl9xLwo4g4/S5Kb0Pi3UNjaLjCLzF5t\n"
    "o8/LeX7UhnfkqXIbnCYs/sisTDoZIy8g7nFuuyqG+6cvvmoV4kRstNpP+9ite0VC\n"
    "rd9TEstrycx4powrIxAXVOm/LzA9Bzdx4+TZ8nm1S3/3cZr8LleqTr2ogZV8Hz7j\n"
    "NmytFBftanvGQAXOAsBZILcvAtFH+xtlg8XrhwqPtt6Di6JeNimgWO5rZoWJCwb1\n"
    "lXC2+2+GBjpASMyjSg9gHB5gnv3Y5IDqPfZ626FM7SEo9eRDjhomvci9+iirjMoh\n"
    "ict6q5y9B9hcOTEIi/LLAG88ps0anq6tOJVeo/u0G4wSRvpShblNrpcmZ2k=\n"
    "-----END CERTIFICATE-----",
}
