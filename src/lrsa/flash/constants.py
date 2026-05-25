"""Flash-flow constants for the native qfil backend."""

MOBILE_TABLET_CATEGORIES = {"phone", "mobile", "tablet", "smart", "smart device"}
QUALCOMM_PLATFORMS = {"qcom", "qualcomm"}
DEFAULT_BOOT_CHAIN_LABELS = (
    "xbl_a",
    "xbl_b",
    "xbl_config_a",
    "xbl_config_b",
    "abl_a",
    "abl_b",
    "uefi_a",
    "uefi_b",
    "tz_a",
    "tz_b",
    "hyp_a",
    "hyp_b",
    "vbmeta_a",
    "vbmeta_b",
    "vbmeta_system_a",
    "vbmeta_system_b",
)

DEFAULT_DECRYPT_PASSWORD = "OSD"
ROM_DECRYPT_MAGIC = 0xFC010203040506CF
ROM_DECRYPT_BUFFER_SIZE = 128 * 1024
