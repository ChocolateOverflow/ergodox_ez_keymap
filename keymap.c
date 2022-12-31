#include QMK_KEYBOARD_H
#include "version.h"

// base layer
#define ALT_Z LALT_T(KC_Z)
#define ALT_SLS RALT_T(KC_SLSH)
#define OS_X LGUI_T(KC_X)
#define OS_SCLN RGUI_T(KC_SCLN)
// thumb cluster
#define CT_ENT LCTL_T(KC_ENT)
#define SH_SPC LSFT_T(KC_SPC)
#define CT_TAB RCTL_T(KC_TAB)
#define SH_BSPC RSFT_T(KC_BSPC)

// VM host key
#define VMHOST KC_RIGHT_CTRL

enum layers {
  BASE,
  LOWER,
  UPPER,
  NAVI,
  NUMPAD,
};

enum custom_keycodes {
  PYPTY = EZ_SAFE_RANGE,
};

// clang-format off
const uint16_t PROGMEM keymaps[][MATRIX_ROWS][MATRIX_COLS] = {
  [BASE] = LAYOUT_ergodox_pretty(
    KC_LEAD, KC_1,    KC_2,    KC_3,    KC_4,    KC_5,    KC_LBRC,          KC_RBRC, KC_6,    KC_7,    KC_8,    KC_9,    KC_0,    KC_PSCR,
    KC_LGUI, KC_Q,    KC_W,    KC_E,    KC_R,    KC_T,    KC_TAB,           KC_ENT,  KC_Y,    KC_U,    KC_I,    KC_O,    KC_P,    KC_RALT,
    KC_ESC,  KC_A,    KC_S,    KC_D,    KC_F,    KC_G,                               KC_H,    KC_J,    KC_K,    KC_L,    OS_SCLN, KC_BSPC,
    KC_LSFT, ALT_Z,   OS_X,    KC_C,    KC_V,    KC_B,    KC_MINS,          KC_EQL,  KC_N,    KC_M,    KC_COMM, KC_DOT,  ALT_SLS, KC_RCTL,
    KC_LEFT, KC_RGHT, KC_HOME, CT_ENT,  SH_SPC,                                               CT_TAB,  SH_BSPC, KC_END,  KC_DOWN, KC_UP,
                                                 KC_MPLY, XXXXXXX,          XXXXXXX, KC_MPLY,
                                                          KC_MPRV,          KC_MNXT,
                                      OSL(LOWER), KC_DEL, KC_PGUP,          KC_PGDN, KC_ESC, OSL(UPPER)
  ),
  [LOWER] = LAYOUT_ergodox_pretty(
    KC_CAPS, _______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_PGUP, KC_TILD, KC_MINS, KC_UNDS, KC_CAPS, _______,          _______, KC_CAPS, KC_PLUS, KC_EQL,  KC_GRV,  KC_PGDN, _______,
    _______, KC_4,    KC_3,    KC_2,    KC_1,    KC_5,                               KC_6,    KC_0,    KC_9,    KC_8,    KC_7,    _______,
    _______, KC_Q,    KC_HOME, KC_DEL,  KC_ESC,  CW_TOGG, _______,          _______, CW_TOGG, KC_ESC,  KC_DEL,  KC_END,  KC_P,    _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, TO(BASE),
                                                 _______, _______,          _______, _______,
                                                          KC_VOLD,          KC_VOLU,
                                       TO(NAVI), _______, _______,          _______, _______, KC_LEAD
  ),
  [UPPER] = LAYOUT_ergodox_pretty(
    KC_CAPS, _______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_F1,   KC_F2,   KC_F3,   KC_F4,   KC_F5,   _______,          _______, KC_F6,   KC_F7,   KC_F8,   KC_F9,   KC_F10,  _______,
    _______, KC_LCBR, KC_LBRC, KC_LPRN, KC_DQUO, KC_PIPE,                            KC_BSLS, KC_QUOT, KC_RPRN, KC_RBRC, KC_RCBR, _______,
    _______, KC_EXLM, KC_AT,   KC_HASH, KC_DLR,  KC_PERC, _______,          _______, KC_CIRC, KC_AMPR, KC_ASTR, KC_F11,  KC_F12,  _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, TO(BASE),
                                                 _______, _______,          _______, _______,
                                                          KC_VOLD,          KC_VOLU,
                                        KC_LEAD, _______, _______,          _______, _______, TO(NUMPAD)
  ),
  [NAVI] = LAYOUT_ergodox_pretty(
    XXXXXXX, _______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, XXXXXXX,
    _______, KC_WH_L, KC_WH_R, KC_WH_U, KC_WH_D, XXXXXXX, XXXXXXX,          XXXXXXX, XXXXXXX, KC_TAB,S(KC_TAB), KC_SPC,  XXXXXXX, _______,
    _______, KC_APP,  KC_BTN3, KC_BTN2, KC_BTN1, XXXXXXX,                            KC_LEFT, KC_DOWN, KC_UP,   KC_RGHT, KC_TAB,  _______,
    _______, KC_ENT,  KC_SPC,  S(KC_TAB),KC_TAB, XXXXXXX, XXXXXXX,          XXXXXXX, KC_ENT,  KC_HOME, KC_END,  KC_PGDN, KC_PGUP, _______,
    QK_BOOT, XXXXXXX, _______, _______, _______,                                              _______, _______, _______, XXXXXXX, TO(BASE),
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
  ),
  [NUMPAD] = LAYOUT_ergodox_pretty(
    XXXXXXX, _______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, XXXXXXX,
    _______, RGB_TOG, KC_MUTE, KC_VOLD, KC_VOLU, XXXXXXX, XXXXXXX,          XXXXXXX, KC_COMM, KC_7,    KC_8,    KC_9,    KC_MINS, _______,
    _______, RGB_VAI, KC_MPLY, KC_MPRV, KC_MNXT, XXXXXXX,                            KC_0,    KC_4,    KC_5,    KC_6,    KC_ENT,  _______,
    _______, RGB_VAD, KC_LNUM, KC_BRID, KC_BRIU, XXXXXXX, XXXXXXX,          XXXXXXX, KC_DOT,  KC_1,    KC_2,    KC_3,    KC_EQL,  _______,
    QK_BOOT, XXXXXXX, _______, _______, _______,                                              _______, _______, _______, XXXXXXX, TO(BASE),

                                                _______, _______,           _______, _______,
                                                         _______,           _______,
                                      TO(BASE), _______, _______,           _______, _______, TO(BASE)
  ),
};
// clang-format on

extern rgb_config_t rgb_matrix_config;

void keyboard_post_init_user(void) {
  rgb_matrix_mode_noeeprom(RGB_MATRIX_SOLID_COLOR);
  rgb_matrix_sethsv_noeeprom(HSV_OFF);
}

bool rgb_matrix_indicators_user(void) {
  if (keyboard_config.disable_layer_led) {
    return false;
  }
  switch (biton32(layer_state)) {
  case BASE:
    rgb_matrix_set_color_all(RGB_RED);
    break;
  case LOWER:
    rgb_matrix_set_color_all(RGB_BLUE);
    break;
  case UPPER:
    rgb_matrix_set_color_all(RGB_GREEN);
    break;
  case NAVI:
    rgb_matrix_set_color_all(RGB_MAGENTA);
    break;
  case NUMPAD:
    rgb_matrix_set_color_all(RGB_YELLOW);
    break;
  default:
    if (rgb_matrix_get_flags() == LED_FLAG_NONE)
      rgb_matrix_set_color_all(RGB_OFF);
    break;
  }
  return true;
}

layer_state_t layer_state_set_user(layer_state_t state) {
  layer_state_t layer = biton(state);
  ergodox_board_led_off();
  ergodox_right_led_1_off();
  ergodox_right_led_2_off();
  ergodox_right_led_3_off();
  switch (layer) {
  // case BASE: no LED
  case LOWER:
    ergodox_right_led_1_on();
    break;
  case UPPER:
    ergodox_right_led_2_on();
    break;
  case NAVI:
    ergodox_right_led_3_on();
    break;
  case NUMPAD:
    ergodox_right_led_1_on();
    ergodox_right_led_2_on();
    break;
  case 5:
    ergodox_right_led_2_on();
    ergodox_right_led_3_on();
    break;
  case 6:
    ergodox_right_led_1_on();
    ergodox_right_led_3_on();
  case 7:
    ergodox_right_led_1_on();
    ergodox_right_led_2_on();
    ergodox_right_led_3_on();
    break;
  default:
    break;
  }
  return state;
};

LEADER_EXTERNS();
void matrix_scan_user(void) {
  LEADER_DICTIONARY() {
    leading = false;
    leader_end();

    SEQ_ONE_KEY(KC_B) { SEND_STRING("#!/bin/bash\n"); }
    SEQ_ONE_KEY(KC_H) { SEND_STRING("python3 -m http.server\n"); }
    SEQ_ONE_KEY(KC_L) { SEND_STRING("nc -lnvp "); }
    SEQ_ONE_KEY(KC_P) { SEND_STRING("#!/usr/bin/python3\n"); }
    SEQ_TWO_KEYS(KC_D, KC_T) { SEND_STRING("../../../../../../etc/passwd"); }
    SEQ_TWO_KEYS(KC_H, KC_P) { SEND_STRING("python3 -m http.server "); }
    SEQ_TWO_KEYS(KC_L, KC_H) { SEND_STRING("127.0.0.1"); }
    SEQ_TWO_KEYS(KC_P, KC_S) { SEND_STRING("ps aux --forest\n"); }
    SEQ_TWO_KEYS(KC_S, KC_S) { SEND_STRING("ss -lntp\n"); }
    SEQ_TWO_KEYS(KC_X, KC_T) { SEND_STRING("export TERM=xterm\n"); }
    SEQ_TWO_KEYS(KC_P, KC_B) {
      SEND_STRING("php://filter/convert.base64-encode/resource=");
    }
    SEQ_TWO_KEYS(KC_P, KC_T) {
      SEND_STRING("python3 -c \"import pty; pty.spawn('/bin/bash')\"\n");
    }
    SEQ_TWO_KEYS(KC_Z, KC_T) {
      SEND_STRING(SS_LCTL("z"));
      SEND_STRING(SS_DELAY(100));
      SEND_STRING("stty raw -echo; fg\n\n");
      SEND_STRING(SS_DELAY(100));
      SEND_STRING("export TERM=xterm\n");
    }
    SEQ_TWO_KEYS(KC_D, KC_D) {
      // delete line
      tap_code(KC_HOME);
      register_code(KC_LSFT);
      tap_code(KC_END);
      unregister_code(KC_LSFT);
      tap_code(KC_DEL);
      tap_code(KC_DEL);
    }
    SEQ_THREE_KEYS(KC_X, KC_S, KC_S) {
      SEND_STRING("<script>alert(window.origin)</script>");
    }
    SEQ_FOUR_KEYS(KC_S, KC_U, KC_I, KC_D) {
      SEND_STRING("find / -perm -4000 2>/dev/null\n");
    }
  }
}
