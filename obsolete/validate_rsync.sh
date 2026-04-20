#!/bin/sh
case "$SSH_ORIGINAL_COMMAND" in
  *\&*)
    echo "Connection closed"
    ;;
  *\;*)
    echo "Connection closed"
    ;;
    rsync*)
    $SSH_ORIGINAL_COMMAND
    ;;
    /usr/local/sbin/rsync_wrapper.sh*)
    $SSH_ORIGINAL_COMMAND
    ;;
  *true*)
    echo $SSH_ORIGINAL_COMMAND
    ;;
  *)
    echo "Connection closed."
    ;;
esac
