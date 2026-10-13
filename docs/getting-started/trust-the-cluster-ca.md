# Trust the cluster CA in a browser

Without Tailscale, the dashboard is served by the gateway itself at
`https://<controller>:8080` with a certificate signed by **your cluster's own
certificate authority**, created during `noo onboard`. No browser knows that
authority, so it shows "Your connection is not private" (Chrome) or
"Warning: Potential Security Risk Ahead" (Firefox). The warning is expected
and the connection is encrypted either way. Trusting the CA makes it go away,
and lets you verify you are talking to your own controller instead of
clicking through.

## The option that needs no CA

If the controller is on a tailnet and onboarding set up `tailscale serve`, the
dashboard is also at `https://<controller>.<your-tailnet>.ts.net`. That name
carries a public certificate issued for the `ts.net` domain, so every browser
accepts it with nothing to install.
Use the CA steps below when you reach the box by IP or hostname on a LAN.

## Step 1: the OS store (what `noo` does)

```bash
noo security trust-ca            # on the machine that runs the browser
```

This copies the CA (`$NOO_PKI_DIR/ca.crt`, under `~/.noo/pki/` on a standalone
install) into the operating system's store: on Linux and WSL2
`/usr/local/share/ca-certificates/mesh-cluster-ca.crt` plus
`update-ca-certificates`; on macOS the System keychain as a trusted root. It
elevates with `sudo` (or `pkexec` on a desktop session). That is enough for
`curl`, `noo` and other system tools, and for Safari and Chrome on macOS and
Windows. It is **not** enough for Chrome/Chromium on Linux or for Firefox,
which keep their own stores: use the sections below.

If the browser is on a different machine than the controller, copy the file
first (`scp <controller>:~/.noo/pki/ca.crt .`) and give `trust-ca` its path:
`noo security trust-ca ./ca.crt`, or follow the per-browser steps with that
file. Only ever copy `ca.crt`; never `ca.key`.

## Linux: Chrome and Chromium

They read the per-user NSS database, not `/etc/ssl`:

```bash
sudo apt install libnss3-tools                 # provides certutil
mkdir -p ~/.pki/nssdb
certutil -d sql:$HOME/.pki/nssdb -N --empty-password    # only if the database does not exist yet
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "noomesh cluster CA" -i ~/.noo/pki/ca.crt
```

Restart the browser fully. Snap or Flatpak builds use a different profile
directory (Snap Chromium: `~/snap/chromium/current/.pki/nssdb`); use that path
in the `-d` argument. Alternatively, in the browser: Settings, Privacy and
security, Manage certificates, Authorities, Import `ca.crt`, tick "Trust this
certificate for identifying websites".

## Linux, macOS, Windows: Firefox

Settings, Privacy and Security, Certificates, View Certificates, Authorities,
Import `ca.crt`, tick "Trust this CA to identify websites".

To make Firefox use the operating system's store instead (so `trust-ca` is
enough), set the `security.enterprise_roots.enabled` preference to `true` in
`about:config`, or deploy it by policy (`/etc/firefox/policies/policies.json`:
`{"policies": {"Certificates": {"ImportEnterpriseRoots": true}}}`). The
Firefox snap reads its own policy directory; the per-browser import above is
the simpler route there.

## macOS

`noo security trust-ca` is enough for Safari and Chrome, which both read the
System keychain. Firefox: see above. To do it by hand:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
```

## Windows

Install the CA into the Windows "Trusted Root Certification Authorities"
store, from an elevated PowerShell, with the file copied to the Windows side:

```powershell
certutil -addstore -f Root ca.crt
```

Edge and Chrome use it immediately. **WSL2 note:** `noo security trust-ca`
run inside WSL2 installs into the Linux distro's store, not Windows, so a
browser on the Windows side needs the command above (or open the dashboard on
its `ts.net` name).

## Verify

```bash
curl -sS https://<controller>:8080/health        # no certificate error = the OS store trusts it
noo health                                       # the CLI over https
openssl x509 -in ~/.noo/pki/ca.crt -noout -subject -fingerprint -sha256
```

In the browser, reload the dashboard: the padlock replaces the warning. Open
the certificate details and check the issuer is "Mesh Cluster CA" and the
fingerprint matches the `openssl` line above. If the warning persists after
importing, the cause is one of: the browser was not restarted; the URL host
(an IP, a different hostname) is not among the names the gateway certificate
was issued for (`noo security pki status`, and re-issue with
`noo security pki issue-gateway <hostname> <ip>`); or a stale CA from an earlier
install is still in the store (`noo security untrust-ca`, then trust again).

Remove the trust again with `noo security untrust-ca` (OS store) and, for
browsers, delete the entry: `certutil -d sql:$HOME/.pki/nssdb -D -n "noomesh cluster CA"`.
