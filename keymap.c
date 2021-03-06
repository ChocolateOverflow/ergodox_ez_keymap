#include QMK_KEYBOARD_H
#include "keymap_belgian.h"
#include "keymap_bepo.h"
#include "keymap_br_abnt2.h"
#include "keymap_canadian_multilingual.h"
#include "keymap_contributions.h"
#include "keymap_croatian.h"
#include "keymap_czech.h"
#include "keymap_danish.h"
#include "keymap_estonian.h"
#include "keymap_french.h"
#include "keymap_german.h"
#include "keymap_german_ch.h"
#include "keymap_hungarian.h"
#include "keymap_italian.h"
#include "keymap_jp.h"
#include "keymap_korean.h"
#include "keymap_lithuanian_azerty.h"
#include "keymap_nordic.h"
#include "keymap_norwegian.h"
#include "keymap_portuguese.h"
#include "keymap_romanian.h"
#include "keymap_russian.h"
#include "keymap_slovak.h"
#include "keymap_slovenian.h"
#include "keymap_spanish.h"
#include "keymap_swedish.h"
#include "keymap_turkish_q.h"
#include "keymap_uk.h"
#include "keymap_us_international.h"
#include "version.h"

#define MT_Z MT(MOD_LCTL | MOD_LSFT, KC_Z)
#define MT_S MT(MOD_LGUI, KC_S)
#define MT_D MT(MOD_LCTL, KC_D)
#define MT_F MT(MOD_LSFT, KC_F)
#define MT_J MT(MOD_RSFT, KC_J)
#define MT_K MT(MOD_RCTL, KC_K)
#define MT_L MT(MOD_RGUI, KC_L)
#define MT_SCLN MT(MOD_RALT, KC_SCLN)
#define TG_LA_CL TOGGLE_LAYER_COLOR
#define WEBUSB WEBUSB_PAIR

enum layers {
  BASE,
  LOWER,
  UPPER,
  NAVI,
  NUMPAD,
  ADJUST,
};

enum custom_keycodes {
  RGB_SLD = EZ_SAFE_RANGE,
  YELLOW,
  RED,
  GREEN,
  BLUE,
  PYPTY,
  TTY_RAW,
};

// clang-format off
const uint16_t PROGMEM keymaps[][MATRIX_ROWS][MATRIX_COLS] = {
  [BASE] = LAYOUT_ergodox_pretty(
    KC_LEAD,        KC_1,     KC_2,     KC_3,     KC_4,     KC_5,   KC_LBRC,              KC_RBRC,  KC_6,     KC_7,     KC_8,       KC_9,     KC_0,     KC_PSCR,
    OSM(MOD_LGUI),  KC_Q,     KC_W,     KC_E,     KC_R,     KC_T,   KC_TAB,               KC_ENT,   KC_Y,     KC_U,     KC_I,       KC_O,     KC_P,     OSM(MOD_LALT),
    KC_GRV,         KC_A,     MT_S,     MT_D,     MT_F,     KC_G,                                   KC_H,     MT_J,     MT_K,       MT_L,     MT_SCLN,  KC_BSLS,
    OSM(MOD_LSFT),  MT_Z,     KC_X,     KC_C,     KC_V,     KC_B,   KC_MINS,              KC_EQL,   KC_N,     KC_M,     KC_COMM,    KC_DOT,   KC_SLSH,  OSM(MOD_RCTL),
    KC_LEFT,        KC_RGHT,  KC_HOME,  KC_ENT,   KC_SPC,                                                     KC_TAB,   KC_BSPC,    KC_END,   KC_DOWN,  KC_UP,
                                        LCTL(KC_LALT),  LM(UPPER,MOD_LGUI),               LM(LOWER,MOD_RGUI), LSFT(KC_RGUI),
                                                        LM(UPPER,MOD_LCTL),               LM(LOWER,MOD_RCTL),
                                            OSL(LOWER), KC_DELETE, KC_PGUP,               KC_PGDOWN,  KC_ESCAPE,  OSL(UPPER)
  ),
  [LOWER] = LAYOUT_ergodox_pretty(
    KC_CAPS, _______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_F11,  KC_TILD, KC_MINS, KC_UNDS, KC_F11,  _______,          _______, KC_F12,  KC_PLUS, KC_EQL,  KC_GRV,  KC_F12,  _______,
    _______, KC_1,    KC_2,    KC_3,    KC_4,    KC_5,                               KC_6,    KC_7,    KC_8,    KC_9,    KC_0,    _______,
    _______, KC_EXLM, KC_AT,   KC_HASH, KC_DLR,  KC_PERC, _______,          _______, KC_CIRC, KC_AMPR, KC_COMM, KC_DOT,  KC_PIPE, _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, TO(BASE),
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(NAVI), _______, _______,          _______, _______, TT(ADJUST)
  ),
  [UPPER] = LAYOUT_ergodox_pretty(
    KC_CAPS, _______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_F1,   KC_F2,   KC_F3,   KC_F4,   KC_F5,   _______,          _______, KC_F6,   KC_F7,   KC_F8,   KC_F9,   KC_F10,  _______,
    _______, KC_LCBR, KC_LBRC, KC_LPRN, KC_DQUO, KC_PIPE,                            KC_BSLS, KC_QUOT, KC_RPRN, KC_RBRC, KC_RCBR, _______,
    _______, KC_EXLM, KC_AT,   KC_HASH, KC_DLR,  KC_PERC, _______,          _______, KC_CIRC, KC_AMPR, KC_ASTR, KC_BSLS, KC_PIPE, _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, TO(BASE),
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                     TT(ADJUST), _______, _______,          _______, _______, TO(NUMPAD)
  ),
  [NAVI] = LAYOUT_ergodox_pretty(
    _______, _______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_WH_U, KC_WH_L, KC_MS_U, KC_WH_R, _______, _______,          _______, _______, KC_HOME, KC_PGDN, KC_PGUP, KC_END,  _______,
    _______, KC_WH_D, KC_MS_L, KC_MS_D, KC_MS_R, _______,                            KC_TAB,  KC_LEFT, KC_DOWN, KC_UP,   KC_RGHT, _______,
    _______, _______, KC_ACL0, KC_ACL1, KC_ACL2, _______, _______,          _______,S(KC_TAB),KC_BTN1, KC_BTN2, KC_BTN3, KC_APP,  _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, TO(BASE),
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), KC_BTN1, _______,          _______, KC_BTN2, TO(NUMPAD)
  ),
  [NUMPAD] = LAYOUT_ergodox_pretty(
    _______, _______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_EXLM, KC_CIRC, KC_PIPE, KC_AMPR, KC_PENT, _______,          _______, KC_PCMM, KC_P7,   KC_P8,   KC_P9,   KC_PCMM, _______,
    _______, KC_PSLS, KC_PAST, KC_PMNS, KC_PPLS, KC_PEQL,                            KC_PDOT, KC_P4,   KC_P5,   KC_P6,   KC_PDOT, _______,
    _______, KC_LT,   KC_GT,   KC_LPRN, KC_RPRN, _______, _______,          _______, KC_P0,   KC_P1,   KC_P2,   KC_P3,   KC_P0,   _______,
    KC_LNUM, _______, _______, _______, _______,                                              _______, _______, _______, _______, TO(BASE),

                                                _______, _______,           _______, _______,
                                                         _______,           _______,
                                      TO(NAVI), _______, _______,           _______, _______, TO(BASE)
  ),

  [ADJUST] = LAYOUT_ergodox_pretty(
    TO(NAVI),_______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, TO(NUMPAD),
    _______, YELLOW,  RED,     GREEN,   BLUE,    _______, _______,          _______, _______, KC_VOLD, KC_VOLU, KC_MUTE, XXXXXXX, _______,
    _______, RGB_TOG,TG_LA_CL, RGB_VAD, RGB_VAI, _______,                            _______, KC_MPRV, KC_MNXT, KC_MPLY, XXXXXXX, _______,
    _______, RGB_SPD, RGB_SPI, RGB_MOD, RGB_SLD, _______, _______,          _______, _______, KC_BRID, KC_BRIU, WEBUSB,  XXXXXXX, _______,
    RESET,   _______, _______, _______, _______,                                              _______, _______, _______, _______, TO(BASE),
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
  ),
};
// clang-format on

extern bool g_suspend_state;
extern rgb_config_t rgb_matrix_config;

void keyboard_post_init_user(void) { rgb_matrix_enable(); }

const uint8_t PROGMEM ledmap[][DRIVER_LED_TOTAL][3] = {
    [0] = {{0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255},
           {0, 255, 255}, {0, 255, 255}, {0, 255, 255}, {0, 255, 255}},

    [1] = {{152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255},
           {152, 255, 255}, {152, 255, 255}, {152, 255, 255}, {152, 255, 255}},

    [2] = {{86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255},
           {86, 255, 255}, {86, 255, 255}, {86, 255, 255}, {86, 255, 255}},

    [3] = {{215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {35, 255, 255},
           {35, 255, 255},  {35, 255, 255},  {35, 255, 255},  {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {35, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {35, 255, 255},
           {35, 255, 255},  {35, 255, 255},  {215, 255, 255}, {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {215, 255, 255},
           {215, 255, 255}, {215, 255, 255}, {215, 255, 255}, {215, 255, 255}},

    [4] = {{43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255},
           {43, 255, 255}, {43, 255, 255}, {43, 255, 255}, {43, 255, 255}},

    [5] = {{129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {152, 255, 255}, {74, 255, 255},
           {0, 245, 245},   {41, 255, 255},  {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255},
           {129, 255, 255}, {129, 255, 255}, {129, 255, 255}, {129, 255, 255}},

};

void set_layer_color(int layer) {
  for (int i = 0; i < DRIVER_LED_TOTAL; i++) {
    HSV hsv = {
        .h = pgm_read_byte(&ledmap[layer][i][0]),
        .s = pgm_read_byte(&ledmap[layer][i][1]),
        .v = pgm_read_byte(&ledmap[layer][i][2]),
    };
    if (!hsv.h && !hsv.s && !hsv.v) {
      rgb_matrix_set_color(i, 0, 0, 0);
    } else {
      RGB rgb = hsv_to_rgb(hsv);
      float f = (float)rgb_matrix_config.hsv.v / UINT8_MAX;
      rgb_matrix_set_color(i, f * rgb.r, f * rgb.g, f * rgb.b);
    }
  }
}

void rgb_matrix_indicators_user(void) {
  if (g_suspend_state || keyboard_config.disable_layer_led) {
    return;
  }
  switch (biton32(layer_state)) {
    case 0:
      set_layer_color(0);
      break;
    case 1:
      set_layer_color(1);
      break;
    case 2:
      set_layer_color(2);
      break;
    case 3:
      set_layer_color(3);
      break;
    case 4:
      set_layer_color(4);
      break;
    case 5:
      set_layer_color(5);
      break;
    default:
      if (rgb_matrix_get_flags() == LED_FLAG_NONE)
        rgb_matrix_set_color_all(0, 0, 0);
      break;
  }
}

bool process_record_user(uint16_t keycode, keyrecord_t *record) {
  switch (keycode) {
    // RGB
    case RGB_SLD:
      if (record->event.pressed) {
        rgblight_mode(1);
      }
      return false;
    case YELLOW:
      if (record->event.pressed) {
        rgblight_mode(1);
        rgblight_sethsv(27, 255, 255);
      }
      return false;
    case RED:
      if (record->event.pressed) {
        rgblight_mode(1);
        rgblight_sethsv(0, 255, 255);
      }
      return false;
    case GREEN:
      if (record->event.pressed) {
        rgblight_mode(1);
        rgblight_sethsv(86, 255, 128);
      }
      return false;
    case BLUE:
      if (record->event.pressed) {
        rgblight_mode(1);
        rgblight_sethsv(172, 255, 255);
      }
      return false;
  }
  return true;
}

uint32_t layer_state_set_user(uint32_t state) {
  uint8_t layer = biton32(state);

  ergodox_board_led_off();
  ergodox_right_led_1_off();
  ergodox_right_led_2_off();
  ergodox_right_led_3_off();
  switch (layer) {
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
    case ADJUST:
      ergodox_right_led_1_on();
      ergodox_right_led_3_on();
      break;
    case 6:
      ergodox_right_led_2_on();
      ergodox_right_led_3_on();
      break;
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

void leader_start(void) {
  ergodox_right_led_1_on();
  ergodox_right_led_2_on();
  ergodox_right_led_3_on();
}

void leader_end(void) {
  ergodox_right_led_1_off();
  ergodox_right_led_2_off();
  ergodox_right_led_3_off();
}
