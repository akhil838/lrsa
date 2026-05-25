"""Device preflight constants."""

QUALCOMM_EDL_IDS = {
    (0x05C6, 0x9008),
    (0x05C6, 0x900E),
    (0x05C6, 0x9006),
}

FASTBOOT_CHECK_STEPS = {
    "FastbootDeviceMatchCheck",
    "FastbootMatchFlashFile",
    "ReadPropertiesInFastboot",
    "BatFileVersionCheck",
}
