import base64
import secrets
import string

MSG_INVALID_USERNAME = "Invalid username or password"
MSG_INVALID_REQUEST = "Invalid request"
MSG_INVALID_AUTH_REQUEST = "Invalid authenticationrequest"
MSG_OPERATION_SUCCESS = "Operation success"
MSG_SERVER_ERROR = "Server error"
MSG_SESSION_ALREADY_STARTED = "Session alreadystarted"
MSG_MOBILE_AUTH_CANCELED = "Mobile authentication canceled"
SETTING_SPANKEY = "SpanKey.EnableLogin=Yes"
MSG_AUTH_SUCCESS = "Authentication success"
RANDOM_STRING = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(10)
)
RANDOM_CONTEXT = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
)
RANDOM_RETRYID = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
)
REGEX_response = (
    r"Server: SSH Public Key Server [0-9.]+ \(WebADM [0-9.]+\)\\r\\nSystem: Linux "
    r"[a-z0-9.\-_]*.x86_64 x86_64 \(\d* bit\)\\r\\nListener: (([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]"
    r"[0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]* \(HTTP\/1.1\)\\r"
    r"\\nUptime: \d*s \(\d* days\)\\r\\nCluster Node: \d*\/\d* \(Session Server\)\\r\\nLocal "
    r"Memory: \d*M \(\d*M total\)\\r\\nShared Memory: \d*M \(\d*M total\)\\r\\nConnectors: OK "
    r"\(\d* alive & 0 down\)"
)
REGEX_SESSION_FORMAT = r"^[a-zA-Z0-9]{16,17}$"
REGEX_TIMEOUT = r"[0-9*]"
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
MSG_INVALID_OR_NOT_FOUND_USER = "Invalid user or user not found"
REGEX_BASE64 = r"^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$"
MSG_SESSION_NOT_STARTED = "Session not started or timedout"
MSG_ENTER_EMERGENCY_OTP = "Enter your EMERGENCY password"

with open("tests/test_file.pdf", "rb") as pdf_file:
    PDF_FILE_BASE64 = base64.b64encode(pdf_file.read()).decode("utf-8")

BASE64_STRING = "dGVzdAo="
SETTINGS_LOGINMODE_LDAP = "OpenOTP.LoginMode=LDAP"
EXCEPTION_FILE_NOT_BASE64 = (
    "<ExceptionInfo TypeError('file parameter is not base64') tblen=2>"
)
EXCEPTION_QR_CODE_NOT_QRCODEFORMAT = (
    "<ExceptionInfo TypeError('qr_format parameter is not QRCodeFormat') tblen=2>"
)
MSG_FILE_NOT_BASE64 = "file parameter is not base64"
MSG_QR_NOT_QRCODEFORMAT = "qr_format parameter is not QRCodeFormat"
MSG_NOT_RIGHT_TYPE = "{} parameter is not {}"
EXCEPTION_NOT_RIGHT_TYPE = "<ExceptionInfo TypeError('{} parameter is not {}') tblen=2>"
TYPE_BASE64_STRING = "base64 string"

REGEX_COORDINATES = r"[0-9\.]*,[0-9\.]*"
REGEX_IPV4 = (
    r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25["
    r"0-5])$"
)
REGEX_ADDRESS = r"^[0-9a-zA-Zà-üÀ-Ü, ]+$"
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
