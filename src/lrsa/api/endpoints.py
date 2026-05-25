"""
API endpoints extracted from lenovo.mbg.service.common.webservices.dll
via .NET IL string table (UTF-16LE decoded).

Base URL: https://lsa.lenovo.com/Interface
All endpoints are .jhtml (Java server-side)
"""

# Auth & Session
RSA_PUBLIC_KEY = "/common/rsa.jhtml"
INIT_TOKEN = "/client/initToken.jhtml"
DISPOSE_TOKEN = "/client/deleteToken.jhtml"
GUEST_LOGIN = "/user/guestLogin.jhtml"
USER_LOGIN = "/login.jhtml"
USER_LOGOUT = "/user/logout.jhtml"
RECORD_LOGIN = "/user/recordLogin.jhtml"
LENOVOID_USER_INFO = "/user/getSFUserInfo.jhtml"
LENOVOID_OAUTH2_CALLBACK = "/user/oauth2/callback.jhtml"
FORGOT_PASSWORD = "/user/forgotPassword.jhtml"
CHANGE_PASSWORD = "/user/changePassword.jhtml"

# Device Info
GET_DEVICE_INFO = "/device/getDeviceInfo.jhtml"
GET_DEVICE_ICON = "/device/getDeviceIcon.jhtml"

# Rescue / Flash / Firmware
RESCUE_GET_MARKET_NAMES = "/rescueDevice/getRescueModelNames.jhtml"
RESCUE_GET_MODEL_NAMES = "/rescueDevice/getModelNames.jhtml"
RESCUE_GET_MODELS_BY_MARKET_NAME = "/rescueDevice/modelListByMarketName.jhtml"
RESCUE_GET_PARAMS_MAPPING = "/rescueDevice/getParamType.jhtml"
RESCUE_GET_ROM_MATCH_PARAMS = "/rescueDevice/getRomMatchParams.jhtml"
RESCUE_GET_NEW_RESOURCE = "/rescueDevice/getNewResource.jhtml"
RESCUE_GET_RESOURCE = "/rescueDevice/getResource.jhtml"
RESCUE_GET_RESOURCE_BY_SN = "/rescueDevice/getNewResourceBySN.jhtml"
RESCUE_GET_RESOURCE_BY_IMEI = "/rescueDevice/getNewResourceByImei.jhtml"
RESCUE_GET_STEP_TIPS = "/rescueDevice/getXamlList.jhtml"
RESCUE_GET_MARKET_SUPPORT = "/rescueDevice/getMarketSupport.jhtml"
RESCUE_GET_MODEL_RECIPE = "/rescueDevice/getRescueModelRecipe.jhtml"
RESCUE_SMART_MARKET_NAMES = "/rescueDevice/smartMarketNames.jhtml"
RESCUE_MODEL_MATCH = "/rescueDevice/modelMatch.jhtml"

# ROM
GET_ROM_LIST = "/priv/getRomList.jhtml"
ROM_CHECK_RULES = "/model/rules.jhtml"
ROM_DOWNLOAD_INFO = "/dataCollection/romDownloadInfo.jhtml"

# Fastboot
GET_FASTBOOT_RECIPE = "/model/getFastbootDataRecipe.jhtml"
GET_FASTBOOT_SUPPORT = "/model/getSupportFastbootByModelName.jhtml"
GET_UPGRADE_FLASH_MATCH = "/model/getUpgradeFlashMatchTypes.jhtml"
GET_DRIVER_CONFIG = "/model/getDriverSpecialConfig.jhtml"

# Client
CHECK_MA_VERSION = "/apk/download.jhtml"
GET_CLIENT_PLUGINS = "/client/getClientPlugins.jhtml"
GET_PLUGIN_CATEGORIES = "/client/getPluginCategoryList.jhtml"
UPDATE_VERSION = "/client/getNextUpdateClientVersion.jhtml"
RENEW_FILE_LINK = "/client/renewFileLink.jhtml"
GET_USER_GUIDE = "/client/getUserGuide.jhtml"
CLIENT_HELP = "/client/clientHelp.jhtml"

# Data Collection / Logging
COLLECTION_ROM_DOWNLOAD = "/dataCollection/romDownloadInfo.jhtml"
COLLECTION_UPLOAD_FILE = "/dataCollection/uploadFile.jhtml"
COLLECTION_RESCUE_SUCCESS = "/dataCollection/rescueSuccessLog.jhtml"
COLLECTION_ASSISTANT_APP = "/dataCollection/assistantApp.jhtml"
COLLECTION_USER_BEHAVIOR = "/dataCollection/addUserBehavior.jhtml"
COLLECTION_BACKUP_RESTORE = "/dataCollection/addBackupRestoreInfo.jhtml"

# Notices
NOTICE_URL = "/notice/getNoticeInfo.jhtml"
NOTICE_BROADCAST = "/notice/getBroadcast.jhtml"

# Feedback
FEEDBACK_LIST = "/feedback/getFeedbackList.jhtml"
FEEDBACK_INFO = "/feedback/getFeedbackInfo.jhtml"
FEEDBACK_SIGNATURE = "/feedback/fileSignatureUrl.jhtml"
FEEDBACK_HELPFUL = "/feedback/replyHelpful.jhtml"
FEEDBACK_UPLOAD = "/feedback/uploadFeedbackInfo.jhtml"
FEEDBACK_GUEST_POST = "/feedback/guestPostFeedbackInfo.jhtml"
FEEDBACK_ISSUE_INFO = "/feedback/getFeedbackIssueInfo.jhtml"

# Survey
SURVEY_TRIGGER = "/survey/getIsNeedTrigger.jhtml"
SURVEY_REFRESH = "/survey/refreshTrigger.jhtml"
SURVEY_QUESTIONS = "/survey/getAllQuestions.jhtml"
SURVEY_RECORD = "/survey/record.jhtml"

# Registered Models
REGISTERED_ADD = "/registeredModel/addModels.jhtml"
REGISTERED_LIST = "/registeredModel/models.jhtml"

# User
GET_SMART_INFO = "/user/getSmartInfo.jhtml"

# VIP / B2B
GET_B2B_INFO = "/vip/getB2BInfo.jhtml"
GET_ACTIVE_B2B = "/vip/getActiveB2BInfos.jhtml"
B2B_BUY = "/vip/buy.jhtml"
B2B_CARD = "/vip/card.jhtml"
GET_ORDER_NUM = "/vip/getOrderNum.jhtml"
GET_ENABLE_ORDER = "/vip/getEnableB2BOrder.jhtml"

# MOLI (AI assistant?)
MOLI_URL = "/moli/getMoliUrl.jhtml"
MOLI_INFO = "/moli/moliAndLena.jhtml"

# YouTube
YOUTUBE_VIDEO = "/model/getYoutubeVideo.jhtml"

# Dictionary
GET_API_INFO = "/dictionary/getApiInfo.jhtml"

# Warranty (external SDE service)
SDE_WARRANTY_XML = '<?xml version="1.0"?><wiInputForm source="spiceworks"><id>LMSA</id><pw>LMSA4IQS</pw><language>English</language><serial>{sn}</serial><service/><parts/><machine/><aod/><entitle/><upma/></wiInputForm>'

# Lenovo ID OAuth
LENOVOID_CALLBACK = "https://passport.lenovo.com/interserver/authen/1.2/getaccountid?lpsust={token}&realm=lmsaclient"

# Web UI
WEB_INDEX = "https://lsa.lenovo.com/lmsa-web/index.jsp"
