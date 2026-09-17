#!/bin/bash
# IndexNow submitter for redos-db — pings Bing/Yandex to crawl our Pages URLs.
KEY=$(cat /tmp/indexnow_key.txt 2>/dev/null || echo "51346cfa7de3c2392b416ddbb4a0bfb4")
HOST="aurelio-nakamura.github.io"
KEYLOC="https://$HOST/redos-db/$KEY.txt"
# collect all <loc> urls from the deployed sitemap
URLS=$(curl -s "https://$HOST/redos-db/sitemap.xml" | grep -o '<loc>[^<]*</loc>' | sed 's/<loc>//;s/<\/loc>//')
python3 - "$KEY" "$HOST" "$KEYLOC" <<PY
import json,sys,urllib.request
key,host,keyloc=sys.argv[1],sys.argv[2],sys.argv[3]
urls="""$URLS""".split()
body={"host":host,"key":key,"keyLocation":keyloc,"urlList":urls}
data=json.dumps(body).encode()
req=urllib.request.Request("https://api.indexnow.org/indexnow",data=data,headers={"Content-Type":"application/json; charset=utf-8"})
try:
    r=urllib.request.urlopen(req,timeout=30)
    print("IndexNow HTTP",r.status,"submitted",len(urls),"urls")
except urllib.error.HTTPError as e:
    print("IndexNow HTTP",e.code,e.read().decode()[:200],"— submitted",len(urls),"urls")
PY
