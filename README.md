In order to log in with smartcards from certain norwegian providers and probably other you will need to do a few things:
1. Install pcsc-lite and start the daemon.
2. Install drivers for the smartcard, probably ccid (or libccid, similar).
3. Install this software and make sure it is started and listening on localhost port 32505.
4. Create and ssl certificate for localhost / 127.0.0.1.
5. Install and set up foreaxample ngingx to listen to port 31505 with https and proxy to port 32505.
6. Install a plugin in your browser to fake Mac OS in the user agent.

Example nginx config for the proxying part:
<pre>
server {
  listen 31505 ssl;
  server_name localhost;

  ssl_certificate /usr/local/etc/localhostssl/cert.pem;
  ssl_certificate_key /usr/local/etc/localhostssl/cert.key;

  location / {
    root html;
    index index.html index.htm;
    proxy_pass http://127.0.0.1:32505;
    add_header Access-Control-Allow-Origin *;
    add_header Access-Control-Allow-Methods GET,POST,OPTIONS;
  }
}
</pre>

To generate a certificate:
1. <pre>
openssl req -x509 -nodes -new -sha256 -days 10240 -newkey rsa:2048 -keyout RootCA.key -out RootCA.pem -subj "/C=NO/CN=Local-Root-CA"
</pre>
2. <pre>
openssl x509 -outform pem -in RootCA.pem -out RootCA.crt
</pre>
3.  Create file domains.ext: <pre>
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
</pre>
4. <pre>
openssl req -new -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.csr -subj "/C=NO/CN=localhost"
</pre>
5. <pre>
openssl x509 -req -sha256 -days 1024 -in localhost.csr -CA RootCA.pem -CAkey RootCA.key -CAcreateserial -extfile domains.ext -out localhost.crt
</pre>
