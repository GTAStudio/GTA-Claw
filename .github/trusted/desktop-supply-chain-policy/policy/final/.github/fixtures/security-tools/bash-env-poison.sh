#!/bin/sh
printf 'executed\n' >"${BASH_ENV_POISON_MARKER:?}"
