#include QMK_KEYBOARD_H
#include "version.h"

// base layer
#define MT_X C_S_T(KC_X)
#define MT_C LALT_T(KC_C)
#define MT_V LGUI_T(KC_V)
#define MT_M RGUI_T(KC_M)
#define MT_COMM RALT_T(KC_COMM)
#define MT_DOT C_S_T(KC_DOT)
// thumb cluster
#define SH_ENT LSFT_T(KC_ENT)
#define CT_SPC LCTL_T(KC_SPC)
#define SH_TAB RSFT_T(KC_TAB)
#define CT_BSPC RCTL_T(KC_BSPC)
// lower layer
#define MT_PGUP LCTL_T(KC_PGUP)
#define MT_HOME LSFT_T(KC_HOME)
#define MT_END RSFT_T(KC_END)
#define MT_PGDN RCTL_T(KC_PGDN)
// mouse layer
#define SCROLL TD(TD_SCROLL)
#define TD_BTN4 TD(TD_MOUSE_4)
#define TD_BTN5 TD(TD_MOUSE_5)

enum layers {
    BASE = 0,
    LOWER,
    UPPER,
    MOUSE,
    NUM,
    NAV,
};

typedef struct {
    bool    is_press_action;
    uint8_t step;
} tap;

static tap dance_state[4];
enum tap_dance_codes {
    TD_SCROLL = 0,
    TD_MOUSE_4,
    TD_MOUSE_5,
};

enum {
    SINGLE_TAP = 1,
    SINGLE_HOLD,
    DOUBLE_TAP,
    DOUBLE_HOLD,
    MORE_TAPS,
};

/***** KEYMAP *****/

// clang-format off
const uint16_t PROGMEM keymaps[][MATRIX_ROWS][MATRIX_COLS] = {
  [BASE] = LAYOUT_ergodox_pretty(
    XXXXXXX, KC_1,    KC_2,    KC_3,    KC_4,    KC_5,    KC_LBRC,          KC_RBRC, KC_6,    KC_7,    KC_8,    KC_9,    KC_0,    KC_PSCR,
    KC_LGUI, KC_Q,    KC_W,    KC_E,    KC_R,    KC_T,    KC_TAB,           KC_ENT,  KC_Y,    KC_U,    KC_I,    KC_O,    KC_P,    KC_RALT,
    KC_ESC,  KC_A,    KC_S,    KC_D,    KC_F,    KC_G,                               KC_H,    KC_J,    KC_K,    KC_L,    KC_SCLN, KC_BSPC,
    KC_LSFT, KC_Z,    MT_X,    MT_C,    MT_V,    KC_B,    KC_MINS,          KC_EQL,  KC_N,    MT_M,    MT_COMM, MT_DOT,  KC_SLSH, KC_RCTL,
    KC_LEFT, KC_RGHT, KC_HOME, SH_ENT,  CT_SPC,                                               SH_TAB,  CT_BSPC, KC_END,  KC_DOWN, KC_UP,
                                                 KC_MPLY, XXXXXXX,          XXXXXXX, KC_MPLY,
                                                          KC_MPRV,          KC_MNXT,
                                      OSL(LOWER), KC_DEL, KC_PGUP,          KC_PGDN, KC_ESC, OSL(UPPER)
  ),
  [LOWER] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_PSCR, KC_TILD, KC_MINS, KC_UNDS, KC_CAPS, _______,          _______, KC_CAPS, KC_PLUS, KC_EQL,  KC_GRV,  KC_PSCR, _______,
    _______, KC_4,    KC_3,    KC_2,    KC_1,    KC_5,                               KC_6,    KC_0,    KC_9,    KC_8,    KC_7,    _______,
    _______, MT_PGUP, MT_HOME, KC_ENT,  KC_ESC,  TO(NAV), _______,          _______, TO(NUM), KC_BSPC, KC_DEL,  MT_END,  MT_PGDN, _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          KC_VOLD,          KC_VOLU,
                                      TO(MOUSE), _______, _______,          _______, _______, CW_TOGG
  ),
  [UPPER] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_F1,   KC_F2,   KC_F3,   KC_F4,   KC_F5,   _______,          _______, KC_F6,   KC_F7,   KC_F8,   KC_F9,   KC_F10,  _______,
    _______, KC_LCBR, KC_LBRC, KC_LPRN, KC_DQUO, KC_PIPE,                            KC_BSLS, KC_QUOT, KC_RPRN, KC_RBRC, KC_RCBR, _______,
    _______, KC_EXLM, KC_AT,   KC_HASH, KC_DLR,  KC_PERC, _______,          _______, KC_CIRC, KC_AMPR, KC_ASTR, KC_F11,  KC_F12,  _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          KC_VOLD,          KC_VOLU,
                                        KC_LEAD, _______, _______,          _______, _______, TO(MOUSE)
  ),
  [MOUSE] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, QK_BOOT,
    _______, KC_PGUP, KC_PGDN, S(KC_TAB),KC_TAB, SCROLL,  XXXXXXX,          XXXXXXX, SCROLL,  KC_TAB,S(KC_TAB), KC_PGDN, KC_PGUP, _______,
    _______, KC_WH_U, KC_WH_D, KC_BTN2, KC_BTN1, C(KC_V),                            C(KC_V), KC_BTN1, KC_BTN2, KC_WH_D, KC_WH_U, _______,
    _______, TD_BTN4, TD_BTN5, KC_ENT,  KC_BTN3, C(KC_C), XXXXXXX,          XXXXXXX, C(KC_C), KC_BTN3, KC_ENT,  TD_BTN4, TD_BTN5, _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
  ),
  [NUM] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, QK_BOOT,
    _______, KC_F1,   KC_F2,   KC_F3,   KC_F4,   XXXXXXX, XXXXXXX,          XXXXXXX, KC_COMM, KC_7,    KC_8,    KC_9,    KC_MINS, _______,
    _______, KC_F5,   KC_F6,   KC_F7,   KC_F8,   XXXXXXX,                            KC_0,    KC_4,    KC_5,    KC_6,    KC_ENT,  _______,
    _______, KC_F9,   KC_F10,  KC_F11,  KC_F12,  XXXXXXX, XXXXXXX,          XXXXXXX, KC_DOT,  KC_1,    KC_2,    KC_3,    KC_EQL,  _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, _______,

                                                _______, _______,           _______, _______,
                                                         _______,           _______,
                                      TO(BASE), _______, _______,           _______, _______, TO(BASE)
  ),
  [NAV] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, QK_BOOT,
    _______, RGB_TOG, KC_MUTE, KC_VOLD, KC_VOLU, KC_PSCR, XXXXXXX,          XXXXXXX, KC_PSCR, KC_TAB,S(KC_TAB), KC_BTN4, KC_BTN5, _______,
    _______, RGB_VAI, KC_MPLY, KC_MPRV, KC_MNXT, KC_LGUI,                            KC_ENT,  KC_LEFT, KC_DOWN, KC_UP,   KC_RGHT, _______,
    _______, RGB_VAD, KC_LNUM, KC_BRID, KC_BRIU, KC_LALT, XXXXXXX,          XXXXXXX, KC_SPC,  KC_HOME, KC_END,  KC_PGDN, KC_PGUP, _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, _______,

                                                _______, _______,           _______, _______,
                                                         _______,           _______,
                                      TO(BASE), _______, _______,           _______, _______, TO(BASE)
  ),
};
// clang-format on

/***** RGB *****/

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
        case MOUSE:
            rgb_matrix_set_color_all(RGB_MAGENTA);
            break;
        case NUM:
            rgb_matrix_set_color_all(RGB_YELLOW);
            break;
        case NAV:
            rgb_matrix_set_color_all(RGB_CYAN);
            break;
        default:
            if (rgb_matrix_get_flags() == LED_FLAG_NONE) rgb_matrix_set_color_all(RGB_OFF);
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
        case MOUSE:
            ergodox_right_led_3_on();
            break;
        case NUM:
            ergodox_right_led_1_on();
            ergodox_right_led_2_on();
            break;
        case NAV:
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

/***** TAP DANCE *****/

uint8_t dance_step(qk_tap_dance_state_t *state) {
    if (state->count == 1) {
        if (state->pressed)
            return SINGLE_HOLD;
        else
            return SINGLE_TAP;
    } else if (state->count == 2) {
        if (state->pressed)
            return DOUBLE_HOLD;
        else
            return DOUBLE_TAP;
    }
    return MORE_TAPS;
}

void td_scr_finished(qk_tap_dance_state_t *state, void *user_data) {
    dance_state[TD_SCROLL].step = dance_step(state);
    switch (dance_state[TD_SCROLL].step) {
        case SINGLE_TAP:
            tap_code(KC_NUM);
            wait_ms(10);
            tap_code(KC_NUM);
            break;
        case DOUBLE_TAP:
            tap_code16(S(KC_PSCR));
            break;
        case SINGLE_HOLD:
        case DOUBLE_HOLD:
            tap_code16(KC_PSCR);
            break;
    }
}

void td_scr_reset(qk_tap_dance_state_t *state, void *user_data) {
    dance_state[TD_SCROLL].step = 0;
}

void td_btn4_finished(qk_tap_dance_state_t *state, void *user_data) {
    dance_state[TD_MOUSE_4].step = dance_step(state);
    switch (dance_state[TD_MOUSE_4].step) {
        case SINGLE_TAP:
        case DOUBLE_TAP:
            register_code16(KC_BTN4);
            break;
        case SINGLE_HOLD:
        case DOUBLE_HOLD:
            register_code16(KC_WH_L);
            break;
    }
}

void td_btn4_reset(qk_tap_dance_state_t *state, void *user_data) {
    wait_ms(10);
    switch (dance_state[TD_MOUSE_4].step) {
        case SINGLE_TAP:
        case DOUBLE_TAP:
            unregister_code16(KC_BTN4);
            break;
        case SINGLE_HOLD:
        case DOUBLE_HOLD:
            unregister_code16(KC_WH_L);
            break;
    }
    dance_state[TD_MOUSE_4].step = 0;
}

void td_btn5_finished(qk_tap_dance_state_t *state, void *user_data) {
    dance_state[TD_MOUSE_5].step = dance_step(state);
    switch (dance_state[TD_MOUSE_5].step) {
        case SINGLE_TAP:
        case DOUBLE_TAP:
            register_code16(KC_BTN5);
            break;
        case SINGLE_HOLD:
        case DOUBLE_HOLD:
            register_code16(KC_WH_R);
            break;
    }
}

void td_btn5_reset(qk_tap_dance_state_t *state, void *user_data) {
    wait_ms(10);
    switch (dance_state[TD_MOUSE_5].step) {
        case SINGLE_TAP:
        case DOUBLE_TAP:
            unregister_code16(KC_BTN5);
            break;
        case SINGLE_HOLD:
        case DOUBLE_HOLD:
            unregister_code16(KC_WH_R);
            break;
    }
    dance_state[TD_MOUSE_5].step = 0;
}

qk_tap_dance_action_t tap_dance_actions[] = {
    [TD_SCROLL]  = ACTION_TAP_DANCE_FN_ADVANCED(NULL, td_scr_finished, td_scr_reset),
    [TD_MOUSE_4] = ACTION_TAP_DANCE_FN_ADVANCED(NULL, td_btn4_finished, td_btn4_reset),
    [TD_MOUSE_5] = ACTION_TAP_DANCE_FN_ADVANCED(NULL, td_btn5_finished, td_btn5_reset),
};

/***** LEADER MACROS *****/

LEADER_EXTERNS();
void matrix_scan_user(void) {
    LEADER_DICTIONARY() {
        leading = false;
        leader_end();

        SEQ_ONE_KEY(KC_B) {
            SEND_STRING("#!/bin/bash\n\n");
        }
        SEQ_ONE_KEY(KC_H) {
            SEND_STRING("python3 -m http.server\n");
        }
        SEQ_ONE_KEY(KC_L) {
            SEND_STRING("nc -lnvp ");
        }
        SEQ_ONE_KEY(KC_P) {
            SEND_STRING("#!/usr/bin/python3\n\n");
        }
        SEQ_TWO_KEYS(KC_D, KC_T) {
            SEND_STRING("../../../../../../etc/passwd");
        }
        SEQ_TWO_KEYS(KC_H, KC_P) {
            SEND_STRING("python3 -m http.server ");
        }
        SEQ_TWO_KEYS(KC_L, KC_H) {
            SEND_STRING("127.0.0.1");
        }
        SEQ_TWO_KEYS(KC_P, KC_S) {
            SEND_STRING("ps aux --forest\n");
        }
        SEQ_TWO_KEYS(KC_S, KC_S) {
            SEND_STRING("ss -lntp\n");
        }
        SEQ_TWO_KEYS(KC_X, KC_T) {
            SEND_STRING("export TERM=xterm\n");
        }
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
        SEQ_THREE_KEYS(KC_X, KC_S, KC_S) {
            SEND_STRING("<script>alert(window.origin)</script>");
        }
        SEQ_FOUR_KEYS(KC_S, KC_U, KC_I, KC_D) {
            SEND_STRING("find / -perm -4000 2>/dev/null\n");
        }
    }
}
