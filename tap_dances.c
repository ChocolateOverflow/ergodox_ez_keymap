enum tap_dance_codes {
    TD_SCROLL_SCREENSHOT = 0,
    TD_ENTER_ESC,
    TD_MOUSE_45,
};

enum {
    SINGLE_TAP = 0,
    SINGLE_HOLD,
    DOUBLE_TAP,
    DOUBLE_HOLD,
    MORE_TAPS,
};

uint8_t dance_step(tap_dance_state_t *state) {
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

static inline void td_tap_or_hold(tap_dance_state_t *state, uint16_t tap_action, uint16_t hold_action) {
    switch (dance_step(state)) {
        case SINGLE_TAP:
        case DOUBLE_TAP:
            tap_code16(tap_action);
            break;
        case SINGLE_HOLD:
        case DOUBLE_HOLD:
            tap_code16(hold_action);
            break;
    }
}

static inline void td_single_or_double(tap_dance_state_t *state, uint16_t single_tap_action, uint16_t double_tap_action) {
    switch (dance_step(state)) {
        case SINGLE_TAP:
        case SINGLE_HOLD:
            tap_code16(single_tap_action);
            break;
        case DOUBLE_TAP:
        case DOUBLE_HOLD:
            tap_code16(double_tap_action);
            break;
    }
}

void td_scroll_screenshot_fn(tap_dance_state_t *state, void *user_data) {
    switch (dance_step(state)) {
        case SINGLE_TAP:
            tap_code(KC_LNUM);
            wait_ms(10);
            tap_code(KC_LNUM);
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

void td_enter_esc_fn(tap_dance_state_t *state, void *user_data) {
    td_single_or_double(state, KC_ENT, KC_ESC);
}

void td_btn45_fn(tap_dance_state_t *state, void *user_data) {
    td_single_or_double(state, KC_BTN4, KC_BTN5);
}

tap_dance_action_t tap_dance_actions[] = {
    [TD_SCROLL_SCREENSHOT] = ACTION_TAP_DANCE_FN(td_scroll_screenshot_fn), //
    [TD_ENTER_ESC]         = ACTION_TAP_DANCE_FN(td_enter_esc_fn),         //
    [TD_MOUSE_45]          = ACTION_TAP_DANCE_FN(td_btn45_fn),             //
};
