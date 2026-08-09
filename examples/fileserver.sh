#!/bin/sh

DOCROOT=$HOME/www

path="$(realpath ${DOCROOT}${PATH_INFO})"
echo $PATH_INFO, $path >&2

case "$path" in
"$DOCROOT"* )
  test -r "$path" && { cat "$path" ; return ; } ;;
esac

printf "Status: 404\r\n\r\n"
