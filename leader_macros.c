void leader_end_user(void) {
    if (leader_sequence_one_key(KC_B)) {
        SEND_STRING("#!/bin/bash\n\n");
    } else if (leader_sequence_one_key(KC_H)) {
        SEND_STRING("python3 -m http.server\n");
    } else if (leader_sequence_one_key(KC_L)) {
        SEND_STRING("nc -lnvp ");
    } else if (leader_sequence_one_key(KC_P)) {
        SEND_STRING("#!/usr/bin/python3\n\n");
    } else if (leader_sequence_two_keys(KC_D, KC_T)) {
        SEND_STRING("../../../../../../etc/passwd");
    } else if (leader_sequence_two_keys(KC_H, KC_P)) {
        SEND_STRING("python3 -m http.server ");
    } else if (leader_sequence_two_keys(KC_L, KC_H)) {
        SEND_STRING("127.0.0.1");
    } else if (leader_sequence_two_keys(KC_P, KC_S)) {
        SEND_STRING("ps aux --forest\n");
    } else if (leader_sequence_two_keys(KC_S, KC_S)) {
        SEND_STRING("ss -lntp\n");
    } else if (leader_sequence_two_keys(KC_X, KC_T)) {
        SEND_STRING("export TERM=xterm\n");
    } else if (leader_sequence_two_keys(KC_P, KC_B)) {
        SEND_STRING("php://filter/convert.base64-encode/resource=");
    } else if (leader_sequence_two_keys(KC_P, KC_T)) {
        SEND_STRING("python3 -c \"import pty; pty.spawn('/bin/bash')\"\n");
    } else if (leader_sequence_two_keys(KC_Z, KC_T)) {
        SEND_STRING(SS_LCTL("z"));
        SEND_STRING(SS_DELAY(100));
        SEND_STRING("stty raw -echo; fg\n\n");
        SEND_STRING(SS_DELAY(100));
        SEND_STRING("export TERM=xterm\n");
    } else if (leader_sequence_three_keys(KC_X, KC_S, KC_S)) {
        SEND_STRING("<script>alert(window.origin)</script>");
    } else if (leader_sequence_four_keys(KC_S, KC_U, KC_I, KC_D)) {
        SEND_STRING("find / -perm -4000 2>/dev/null\n");
    }
}
