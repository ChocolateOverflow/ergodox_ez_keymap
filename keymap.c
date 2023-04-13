#include QMK_KEYBOARD_H
#include "version.h"

#include "leader_macros.c"
#include "tap_dances.c"

#define STAB S(KC_TAB)
// home mods row
#define MT_Z LALT_T(KC_Z)
#define MT_X LGUI_T(KC_X)
#define MT_D LCTL_T(KC_D)
#define MT_F LSFT_T(KC_F)
#define MT_J LSFT_T(KC_J)
#define MT_K LCTL_T(KC_K)
#define MT_L LGUI_T(KC_L)
#define MT_SCLN LALT_T(KC_SCLN)
// thumb cluster
#define NAV_ENT LT(NAV, KC_ENT)
#define MT_SPC LCTL_T(KC_SPC)
#define MT_TAB LSFT_T(KC_TAB)
#define FN_BSPC LT(FN, KC_BSPC)
// NUMPLUS layer home row mods
#define MT_4 LALT_T(KC_4)
#define MT_3 LGUI_T(KC_3)
#define MT_2 LCTL_T(KC_2)
#define MT_1 LSFT_T(KC_1)
#define MT_0 LSFT_T(KC_0)
#define MT_9 LCTL_T(KC_9)
#define MT_8 LALT_T(KC_8)
#define MT_7 LGUI_T(KC_7)
// Layer access
#define LT_NUM LT(NUMPAD, KC_F12)
#define LT_MED LT(MED, KC_F12)
// mouse layer
#define CT_ENT LCTL_T(KC_ENT)
#define SH_SPC LSFT_T(KC_SPC)
#define SH_TAB LSFT_T(KC_TAB)
#define CT_DEL LCTL_T(KC_DEL)
#define TD_SCR TD(TD_SCROLL_SCREENSHOT)
#define TD_ENT TD(TD_ENTER_ESC)
#define TD_BTN45 TD(TD_MOUSE_45)

enum layers {
    BASE = 0,
    NUMPLUS,
    SYMBOL,
    NAV,
    FN,
    NUMPAD,
    MED,
    MOUSE,
};

/***** KEYMAP *****/

// clang-format off
const uint16_t PROGMEM keymaps[][MATRIX_ROWS][MATRIX_COLS] = {

  [BASE] = LAYOUT_ergodox_pretty(
    XXXXXXX, KC_1,    KC_2,    KC_3,    KC_4,    KC_5,    KC_LBRC,          KC_RBRC, KC_6,    KC_7,    KC_8,    KC_9,    KC_0,    KC_PSCR,
    KC_LGUI, KC_Q,    KC_W,    KC_E,    KC_R,    KC_T,    KC_TAB,           KC_ENT,  KC_Y,    KC_U,    KC_I,    KC_O,    KC_P,    KC_LALT,
    KC_ESC,  KC_A,    KC_S,    MT_D,    MT_F,    KC_G,                               KC_H,    MT_J,    MT_K,    MT_L,    MT_SCLN, KC_BSPC,
    KC_LSFT, MT_Z,    MT_X,    KC_C,    KC_V,    KC_B,    KC_BSPC,          KC_SPC,  KC_N,    KC_M,    KC_COMM, KC_DOT,  KC_SLSH, KC_RCTL,
    KC_LEFT, KC_RGHT, KC_HOME, NAV_ENT, MT_SPC,                                               MT_TAB,  FN_BSPC, KC_END,  KC_DOWN, KC_UP,
                                                 KC_MPLY, XXXXXXX,          XXXXXXX, KC_MPLY,
                                                          KC_MPRV,          KC_MNXT,
                                    OSL(NUMPLUS), KC_DEL, KC_PGUP,          KC_PGDN, KC_ESC, OSL(SYMBOL)
  ),

  [NUMPLUS] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, KC_F1,   KC_F2,   KC_F3,   KC_F4,   KC_F5,   _______,          _______, KC_F6,   KC_F7,   KC_F8,   KC_F9,   KC_F10,  _______,
    _______, MT_4,    MT_3,    MT_2,    MT_1,    KC_5,                               KC_6,    MT_0,    MT_9,    MT_8,    MT_7,    _______,
    _______, LT_NUM,  KC_F11,  KC_ESC,  KC_ENT,  KC_COLN, _______,          _______, KC_SPC,  KC_BSPC, KC_DEL,  KC_HOME, KC_END,  _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          KC_VOLD,          KC_VOLU,
                                      TO(MOUSE), _______, _______,          _______, _______, CW_TOGG
  ),

  [SYMBOL] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, _______,          _______, _______, _______, _______, _______, _______, _______,
    _______, XXXXXXX, KC_CIRC, KC_PLUS, KC_EQL,  KC_AT,   _______,          _______, _______, KC_LBRC, KC_RBRC, KC_DLR,  XXXXXXX, _______,
    _______, KC_TILD, KC_GRV,  KC_QUOT, KC_DQUO, KC_BSLS,                            KC_PIPE, KC_LPRN, KC_RPRN, KC_HASH, KC_EXLM, _______,
    _______, KC_LT,   KC_GT,   KC_MINS, KC_UNDS, KC_PERC, _______,          _______, KC_AMPR, KC_LCBR, KC_RCBR, KC_ASTR, LT_MED,  _______,
    _______, _______, _______, _______, _______,                                              _______, _______, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          KC_VOLD,          KC_VOLU,
                                        QK_LEAD, _______, _______,          _______, _______, TO(MOUSE)
  ),

  [NAV] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, _______,
    _______, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, _______,          _______, XXXXXXX, KC_ENT,  KC_SPC,  KC_BTN4, KC_BTN5, _______,
    _______, KC_LALT, KC_LGUI, KC_LCTL, KC_LSFT, XXXXXXX,                            KC_LEFT, KC_DOWN, KC_UP,   KC_RGHT, KC_ESC,  _______,
    _______, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, TO(NAV), _______,          _______, KC_TAB,  KC_HOME, KC_END,  KC_PGDN, KC_PGUP, _______,
    _______, _______, _______, XXXXXXX, XXXXXXX,                                              XXXXXXX, XXXXXXX, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
  ),

  [FN] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, _______,
    _______, KC_F1,   KC_F2,   KC_F3,   KC_F4,   XXXXXXX, _______,          _______, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, _______,
    _______, KC_F5,   KC_F6,   KC_F7,   KC_F8,   XXXXXXX,                            XXXXXXX, KC_LSFT, KC_LCTL, KC_LGUI, KC_LALT, _______,
    _______, KC_F9,   KC_F10,  KC_F11,  KC_F12,  XXXXXXX, _______,          _______, TO(FN),  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, _______,
    _______, _______, _______, XXXXXXX, XXXXXXX,                                              XXXXXXX, XXXXXXX, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
  ),

  [NUMPAD] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, _______,
    _______, KC_LNUM, KC_UNDS,  KC_ENT,  KC_EQL, XXXXXXX, _______,          _______, KC_COMM, KC_7,    KC_8,    KC_9,    KC_MINS, _______,
    _______, KC_LALT, KC_LGUI, KC_LCTL, KC_LSFT, KC_SPC,                             KC_BSPC, KC_4,    KC_5,    KC_6,    KC_ENT,  _______,
    _______, KC_SLSH, KC_ASTR, KC_PLUS, KC_MINS, TO(NUMPAD), _______,       _______, KC_DOT,  KC_1,    KC_2,    KC_3,    KC_EQL,  _______,
    _______, _______, _______, XXXXXXX, XXXXXXX,                                              KC_0,    XXXXXXX, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
  ),

  [MED] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, _______,
    _______, XXXXXXX, KC_MUTE, KC_VOLD, KC_VOLU, XXXXXXX, _______,          _______, XXXXXXX, KC_VOLD, KC_VOLU, KC_MUTE, XXXXXXX, _______,
    _______, XXXXXXX, KC_MPLY, KC_MPRV, KC_MNXT, XXXXXXX,                            XXXXXXX, KC_MPRV, KC_MNXT, KC_MPLY, XXXXXXX, _______,
    _______, XXXXXXX, _______, KC_BRID, KC_BRIU, TO(MED), _______,          _______, TO(MED), KC_BRID, KC_BRIU, _______, XXXXXXX, _______,
    _______, _______, _______, XXXXXXX, XXXXXXX,                                              XXXXXXX, XXXXXXX, _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
  ),

  [MOUSE] = LAYOUT_ergodox_pretty(
    TO(BASE),_______, _______, _______, _______, _______, XXXXXXX,          XXXXXXX, _______, _______, _______, _______, _______, QK_BOOT,
    KC_LGUI, KC_WH_U, TD_BTN45,C(KC_Y), C(KC_Z), TD_SCR,  _______,          _______, TD_SCR,  C(KC_Z), C(KC_Y), TD_BTN45,KC_WH_U, KC_LGUI,
    KC_LCTL, KC_WH_D, KC_BTN3, KC_BTN2, KC_BTN1, TD_ENT,                             TD_ENT,  KC_BTN1, KC_BTN2, KC_BTN3, KC_WH_D, KC_LCTL,
    KC_LSFT, C(KC_A), C(KC_X), C(KC_C), C(KC_V), KC_TAB,  _______,          _______, KC_TAB,  C(KC_V), C(KC_C), C(KC_X), C(KC_A), KC_LSFT,
    _______, _______, _______, CT_DEL,  SH_SPC,                                               SH_SPC,  CT_DEL,  _______, _______, _______,
                                                 _______, _______,          _______, _______,
                                                          _______,          _______,
                                       TO(BASE), _______, _______,          _______, _______, TO(BASE)
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
        case NUMPLUS:
            rgb_matrix_set_color_all(RGB_BLUE);
            break;
        case SYMBOL:
            rgb_matrix_set_color_all(RGB_GREEN);
            break;
        case NAV:
            rgb_matrix_set_color_all(RGB_ORANGE);
            break;
        case FN:
            rgb_matrix_set_color_all(RGB_CYAN);
            break;
        case NUMPAD:
            rgb_matrix_set_color_all(RGB_PINK);
            break;
        case MED:
            rgb_matrix_set_color_all(RGB_PURPLE);
            break;
        case MOUSE:
            rgb_matrix_set_color_all(RGB_MAGENTA);
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
        case NUMPLUS:
            ergodox_right_led_1_on();
            break;
        case SYMBOL:
            ergodox_right_led_2_on();
            break;
        case NAV:
            ergodox_right_led_3_on();
            break;
        case FN:
            ergodox_right_led_1_on();
            ergodox_right_led_2_on();
            break;
        case NUMPAD:
            ergodox_right_led_2_on();
            ergodox_right_led_3_on();
            break;
        case MED:
            ergodox_right_led_1_on();
            ergodox_right_led_3_on();
        case MOUSE:
            ergodox_right_led_1_on();
            ergodox_right_led_2_on();
            ergodox_right_led_3_on();
            break;
        default:
            break;
    }
    return state;
};

/***** COMBOS *****/

#define COMBO_COUNT 3
enum combos {
  JK_ESC_COMBO,
  COPY_COMBO,
  PASTE_COMBO,
  COMBO_LENGTH
};
uint16_t COMBO_LEN = COMBO_LENGTH;

const uint16_t PROGMEM jk_esc_combo[] = {MT_J, MT_K, COMBO_END};
const uint16_t PROGMEM copy_combo[] = {MT_X, KC_C, COMBO_END};
const uint16_t PROGMEM paste_combo[] = {MT_X, KC_V, COMBO_END};

combo_t key_combos[COMBO_COUNT] = {
  [JK_ESC_COMBO] = COMBO(jk_esc_combo, KC_ESC),
  [COPY_COMBO] = COMBO(copy_combo, C(S(KC_C))),
  [PASTE_COMBO] = COMBO(paste_combo, C(S(KC_V))),
};
