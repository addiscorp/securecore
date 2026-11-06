#!/bin/sh
# The version in the tree (VERSION). Release tags are v<this> (stable) or
# v<this>-canary-<7-char sha>.
set -eu
tr -d ' \n' < "$(dirname "$0")/../VERSION"
