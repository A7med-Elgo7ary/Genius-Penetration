#!/bin/bash
# Start ZAP daemon with API enabled for Genius-Penetration project

echo "Starting OWASP ZAP daemon on 127.0.0.1:8080 with API key..."
zap -daemon -host 127.0.0.1 -port 8080 -config api.key=genius-penetration-zap-key \
    -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true &

echo "ZAP daemon started. API key: genius-penetration-zap-key"
echo "To check if ZAP is running: curl -k 'http://localhost:8080/JSON/core/view/version/' -H 'X-ZAP-API-Key: genius-penetration-zap-key'"
