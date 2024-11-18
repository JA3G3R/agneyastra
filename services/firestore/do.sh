#! /bin/bash

streamToken=$1

curl 'https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8&database=projects%2Fagneyastra-testing2%2Fdatabases%2F(default)&gsessionid=XP3FLqBeXCvoKkl0hlQqMhekt8rK2JMn9Ek0YqDLXR4&SID=Rikzyf0gP74RoQMLqNnZtQ&RID=47523&AID=1&zx=aoepuihe44gj&t=1' \
  -H 'accept: */*' \
  -H 'accept-language: en-US,en;q=0.9' \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -H 'dnt: 1' \
  -H 'origin: http://127.0.0.1:5000' \
  -H 'pragma: no-cache' \
  -H 'priority: u=1, i' \
  -H 'referer: http://127.0.0.1:5000/' \
  -H 'sec-ch-ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Windows"' \
  -H 'sec-fetch-dest: empty' \
  -H 'sec-fetch-mode: cors' \
  -H 'sec-fetch-site: cross-site' \
  -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
  -H 'x-client-data: CJK2yQEIorbJAQipncoBCLWIywEIlqHLAQiBo8sBCJv+zAEIhaDNAQjQxc4BCNHHzgEI9c/OARj0yc0B' \
  --data-raw 'count=1&ofs=1&req0___data__=%7B%22streamToken%22%3A%22'$1'%22%2C%22writes%22%3A%5B%7B%22delete%22%3A%22projects%2Fagneyastra-testing2%2Fdatabases%2F(default)%2Fdocuments%2Fyour_collection_name%2FFxCdorokByl4mxtrpkNB%22%7D%5D%7D'