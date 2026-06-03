# Anglerfish-AI ISO

`./build.sh` (at the repo root) produces a bootable **Debian 12 (bookworm)**
ISO that:

1. Boots a minimal text console.
2. Runs `anglerfish-wizard` on tty1 before any networked service comes up
   (`anglerfish-firstboot.service`); the wizard owns the console until it
   has written the env file, then hands `getty@tty1` back.
3. Brings up the nftables firewall (`anglerfish-firewall.service`) from the
   wizard's interface answers.
4. Starts the bridge, the dashboard, and the SSH lure
   (`anglerfish-bridge`/`-dashboard`/`-lure.service`), and arms the geo
   database update timer.

## Why a container

The build runs entirely inside a **pinned Debian bookworm container**
(`iso/Dockerfile`). This is the single source of truth for the live-build
toolchain, so the ISO is identical whether you build from WSL, CI, or a
fresh VM. It is not optional polish: Debian's `live-build` accepts options
(`--bootloaders`, `--image-name`) that the Ubuntu CI runner's older fork
rejects, and the host dev box here is Debian *trixie* while the ISO targets
*bookworm*. Pinning the toolchain in a container removes all of that drift.

## Building

Requirements: **Docker** with privileged-container support (live-build
needs loop devices + chroot). On Docker Desktop, enable WSL integration for
your distro; on Linux, add your user to the `docker` group.

```bash
./build.sh                 # ISO without on-host Ollama (trusted-remote)
./build.sh --with-ollama   # bundle Ollama in the image (~5 GB)
./build.sh --sign          # additionally cosign-sign the ISO (needs OIDC)
```

`./build.sh` builds the pinned container (cached on the `iso/Dockerfile`
content hash), then runs `iso/build.sh` inside it with `--privileged`. The
finished ISO + `.sha256` land in **`./output/`**, owned by you (the
container runs as root but the files are chowned back).

Do not run `iso/build.sh` directly on a host: that reintroduces the
live-build version drift the container exists to eliminate.

## Reproducibility

- **Build environment:** the base image is pinned by a dated tag *and* its
  content digest (`debian:bookworm-YYYYMMDD-slim@sha256:...` in
  `iso/Dockerfile`), so every machine uses the exact same toolchain.
- **Current target:** *functionally* identical ISOs everywhere (same
  pinned toolchain, same recipe). The chroot's own packages are pulled from
  `deb.debian.org` at build time, so they track bookworm point releases.
- **Path to bit-identical:** pin the chroot's apt to a dated
  `snapshot.debian.org` mirror (`--mirror-bootstrap`/`--mirror-binary` in
  `iso/auto/config`) and set `SOURCE_DATE_EPOCH`. This is the documented
  next step, deferred so the functional build lands first.

### Refreshing the pins

```bash
# Resolve the current bookworm-slim digest, then update the dated tag and
# the @sha256 in iso/Dockerfile together:
docker buildx imagetools inspect debian:bookworm-slim
```

## Verifying

```bash
cd output
sha256sum -c anglerfish-ai-<version>.iso.sha256

# If signed (./build.sh --sign or the CI Build ISO workflow):
cosign verify-blob \
  --signature   anglerfish-ai-<version>.iso.sig \
  --certificate anglerfish-ai-<version>.iso.pem \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer-regexp '.*' \
  anglerfish-ai-<version>.iso
```

## Booting

The ISO is a BIOS+UEFI hybrid (`syslinux` for BIOS El Torito, `grub-efi`
for UEFI). `dd` it to a USB stick or boot it directly in QEMU / VirtualBox
/ VMware. On first boot the wizard takes over tty1 and walks the operator
through the responsible-use terms, NIC selection, Ollama configuration, and
secret generation.

## Persisting to disk

The ISO boots as an ephemeral live system: the root filesystem is a tmpfs
overlay on the read-only squashfs, so captured intel, the wizard secrets,
the credential AES key, the SSH host keys, and the append-only audit log are
all lost on reboot. That is the right default for a throwaway evaluation,
but a deployed sensor needs persistence.

`anglerfish-install` converts the running live appliance into a normal
on-disk Debian system. It is baked into the image at
`/usr/local/sbin/anglerfish-install`.

```sh
# Boot the ISO, complete the first-boot wizard (so its config is captured),
# then persist the appliance to a disk.
sudo anglerfish-install /dev/sda            # prompts for confirmation
sudo anglerfish-install --yes /dev/nvme0n1  # unattended
sudo reboot                                 # remove the install media first
```

### Layout: OS and data are separate

The OS root and the durable state live on different partitions, so the OS
can be reimaged without losing intel:

| Part | Type | Label | Holds |
| --- | --- | --- | --- |
| p1 | `ef02` | BIOS-boot (1M) | GRUB core image for legacy BIOS |
| p2 | `ef00` | ESP (512M) | UEFI bootloader |
| p3 | `8300` | `anglerfish-root` | the OS (reimageable) |
| p4 | `8300` | `anglerfish-data` | the durable state |

The three state directories are bind-mounted off the data partition via
`fstab`, so the canonical paths are unchanged:

```
/data/etc -> /etc/anglerfish        (wizard config, secrets, credential key)
/data/lib -> /var/lib/anglerfish    (sessions DB, lure keys, geo data)
/data/log -> /var/log/anglerfish    (append-only audit log)
```

Root defaults to 16G; the data partition takes the rest. Override with
`--root-size` (e.g. larger for bundled Ollama models): `--root-size 40G`.

### Reimaging without losing intel

On reinstall, an existing `anglerfish-data` partition is detected by label
and **preserved**: only the OS root and ESP are reformatted. Rerun the same
command to push a new OS build onto a deployed sensor and keep every captured
session.

```sh
sudo anglerfish-install /dev/sda             # reimage OS, keep data
sudo anglerfish-install --wipe-data /dev/sda # purge data, start clean
```

### What it does

1. GPT-partitions the target (fresh install) or reformats only root + ESP
   (preserve), per the layout above.
2. `rsync`s the live root filesystem to the new root, excluding the
   pseudo-filesystems and live-only scratch dirs, then recreates the empty
   mount points the kernel mounts over at boot.
3. Relocates the state directories onto the data partition (fresh) or reuses
   the preserved ones, leaving the canonical paths as empty bind targets.
4. Writes an `fstab` keyed by filesystem UUID, including the three bind
   mounts ordered after `/data`.
5. Chroots in to convert live to normal boot: purges
   `live-boot`/`live-config`, generates fresh per-host SSH host keys
   (`ssh-keygen -A`, so the operator sshd starts and every deployment gets
   unique keys), regenerates a normal initramfs, and installs GRUB for both
   UEFI (`--removable`) and legacy BIOS.

It refuses to install onto the live media itself, and partition device naming
handles both `sdX` and `nvme0n1pN` layouts. Verified by an automated QEMU
cycle (`iso/test/`): a fresh install into a blank disk boots in both SeaBIOS
and OVMF and reaches the first-boot wizard from the on-disk root; a second
install preserves the data partition while reimaging the OS; and `--wipe-data`
purges it.

## App staging

The app is staged into the image at `/opt/anglerfish/src` via
`config/includes.chroot` (populated by `iso/build.sh` from an allowlist:
`src/`, `systemd/`, `pyproject.toml`, `README.md`, `LICENSE`, `uv.lock`).
`live-build` copies `config/includes.chroot/*` into the chroot before the
`normal/` hooks run and into the booted image, so the venv install and the
systemd units both read the local tree with **no boot-time network**.

## Files

| Path | Purpose |
| --- | --- |
| `../build.sh` | Host orchestrator: builds + runs the pinned container |
| `Dockerfile` | Pinned bookworm build environment (live-build toolchain) |
| `build.sh` | In-container live-build driver (do not run on a host) |
| `auto/config` | `lb config` overrides (Debian bookworm, mirrors, BIOS+UEFI) |
| `auto/clean` | `lb clean` overrides |
| `auto/build` | `lb build` overrides + log capture |
| `config/package-lists/anglerfish.list.chroot` | Chroot packages (kernel, live-boot/config, runtime) |
| `config/hooks/normal/0010-anglerfish-user.hook.chroot` | Creates the `anglerfish` system user |
| `config/hooks/normal/0020-install-anglerfish.hook.chroot` | Installs the app venv from `/opt/anglerfish/src` |
| `config/hooks/normal/0050-systemd-units.hook.chroot` | Installs + enables the systemd units |
| `config/hooks/normal/0060-install-ollama.hook.chroot` | Optional on-host Ollama (`--with-ollama`) |
| `config/includes.chroot/` | Files copied verbatim into the image |
| `config/includes.chroot/usr/local/sbin/anglerfish-install` | Persist the live appliance to disk (BIOS+UEFI) |
| `test/qmp_screendump.py` | Boot-test helper: captures the guest console over QMP |
