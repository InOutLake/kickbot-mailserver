# Mail server

This is a simple mail server with an HTTP API to create accounts. The API is very basic and kinda ugly, (errors are not caught, no tests) but I’m not a Go expert and didn’t spend much time on it. I chose Go because I’m tight on RAM 😅

To set it up, first put your SSL certificates into the `config` folder:
```bash
mkdir config
mv /path/to/ssl config/ssl
```

Or generate self-signed ones (don’t forget to replace the domain with your DNS):
```bash
mkdir config
cd config
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
  -nodes -keyout ssl/key.pem -out ssl/cert.pem \
  -subj "/CN=mail.some.com" \
  -addext "subjectAltName=DNS:mail.some.com"
```

Then create a `.env` file — there’s an example included.

Mail is accessible on port `25` (to receive emails) and `143` (via IMAP).  
The API runs on port `8080` by default.

Also — don’t make my mistake and try to deploy this on a residential IP. Turns out port `25` is usually blocked by ISPs 😓
