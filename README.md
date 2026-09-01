# FreeOTP Export

Turn a [FreeOTP](https://freeotp.github.io/) (Android) backup back into `otpauth://` URIs and QR codes.

```
pip install -r requirements.txt
python freeotp_export.py externalBackup.xml
```

You will be asked for the backup password: the master password you created when FreeOTP 2.x was
first launched (the Backup menu itself never asks for it). The script writes `externalBackup.html`
next to the input, a single self-contained page that lists every token; click one to enlarge its
QR code and see the live code. It also prints each token's URI and current code so you can compare
with the app.

Options:

```
--html FILE     HTML output path (default: <backup name>.html)
--title TEXT    HTML page title
--qr            also draw QR codes in the terminal
-o DIR          also write one QR image per token (+ uris.txt); --format png|svg|pdf, --scale N
--json          print tokens as JSON instead of writing HTML
--filter TEXT   only tokens whose issuer/label contains TEXT
--extras        keep FreeOTP-only params (lock/color/image) in the URIs
-p PASSWORD     skip the password prompt
```

Everything this tool produces contains plaintext OTP secrets. Keep the output as private as a
password and delete it when you are done.
