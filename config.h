/*
  Set any config.h overrides for your specific keymap here.
  See config.h options at https://docs.qmk.fm/#/config_options?id=the-configh-file
*/
#define ORYX_CONFIGURATOR
#define RETRO_TAPPING

#define PERMISSIVE_HOLD

#undef RGB_DISABLE_TIMEOUT
#define RGB_DISABLE_TIMEOUT 60000

#define USB_SUSPEND_WAKEUP_DELAY 0
#undef MOUSEKEY_WHEEL_DELAY
#define MOUSEKEY_WHEEL_DELAY 200

#undef MOUSEKEY_WHEEL_INTERVAL
#define MOUSEKEY_WHEEL_INTERVAL 50

#define CAPS_LOCK_STATUS
#define FIRMWARE_VERSION u8"ENRen/KLpAw"
#define RGB_MATRIX_STARTUP_SPD 60
