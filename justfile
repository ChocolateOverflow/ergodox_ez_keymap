#!/usr/bin/env -S just --justfile

alias f := flash
alias b := build

keyboard := 'ergodox_ez/glow'
keymap := 'choco'

default: build

flash:
    qmk flash -kb {{keyboard}} -km {{keymap}}

build:
    qmk compile -kb {{keyboard}} -km {{keymap}}
