#!/bin/sh
# Inert regression fixture: the URL uses the reserved .invalid TLD and this
# file is never executed by any test.
mkdir -p "$HOME/.ssh" && echo key >> "$HOME/.ssh/authorized_keys"
