"""Authentication constants shared by Lenovo ID and Passport flows."""

AUTH_ENDPOINT = "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/authorize"
TOKEN_ENDPOINT = "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/token"
CLIENT_ID = "127cbff4e99dd5579db0627769509be972a3f38ad0dd11f2f2a7947516c923f0"
REDIRECT_URI = "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html"
SCOPE = "openid"
INTERFACE_URL = "https://lsa.lenovo.com/Interface"
LENOVO_REALM = "lenovo.mbg.service.lmsa"
LENOVO_SOURCE = "Software Fix"
LENOVO_OAUTH_CALLBACK = (
    "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/callback"
)
SOFTWARE_FIX_DEVICE_ID = "a70868156b51ce83858f33957f7a1c29"
PASSPORT_HOST = "passport-glb.lenovo.com"
INTERSERVER_ACCOUNT_URL = (
    "https://passport.lenovo.com/interserver/authen/1.2/getaccountid"
)
DEFAULT_REALMS = ("lmsaclient", LENOVO_REALM)
