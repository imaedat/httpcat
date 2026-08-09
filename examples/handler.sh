#!/bin/sh

send_response()
{
  code="$1"
  body="$2"
  type="${3:-text/plain}"

  case "$code" in
  200 )
    status_line="200 OK"
    ;;
  400 )
    status_line="400 Bad Request"
    ;;
  503 )
    status_line="503 Service Unavailable"
    ;;
  * )
    status_line="500 Internal Server Error"
    ;;
  esac

  len=$(echo -n "$body" | wc -c)
  printf "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s" \
    "$status_line" "$type" "$len" "$body"
}

echo_request_env()
{
  json='{
  "REQUEST_METHOD": "'$REQUEST_METHOD'",
  "REQUEST_URI": "'$REQUEST_URI'",
  "PATH_INFO": "'$PATH_INFO'",
  "QUERY_STRING": "'$QUERY_STRING'",
  "CONTENT_TYPE": "'$CONTENT_TYPE'",
  "CONTENT_LENGTH": '$CONTENT_LENGTH',
  "SERVER_PROTOCOL": "'$SERVER_PROTOCOL'",
  "SERVER_NAME": "'$SERVER_NAME'",
  "SERVER_PORT": '$SERVER_PORT',
  "REMOTE_ADDR": "'$REMOTE_ADDR'",
  "REMOTE_PORT": '$REMOTE_PORT',
  "HTTPS": "'$HTTPS'",
  "HTTPS_X509_COMMONNAME": "'$HTTPS_X509_COMMONNAME'",
  "HTTPS_X509_SAN_DNS": "'$HTTPS_X509_SAN_DNS'"
}'

  send_response 200 "$json" "application/json"
}

main()
{
  if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ]; then
    request=$(cat)
    echo "$request" >&2
  fi
  echo_request_env
}

main "$@"

# vi: set sw=2 ts=2 et:
