# Live-build ISO recipe

`./build.sh` produces a bootable Debian 12 ISO that:

1. Boots a minimal text console.
2. Runs `anglerfish-wizard run` on tty1 before any networked service
   comes up (`anglerfish-firstboot.service`).
3. Brings up the nftables firewall (`anglerfish-firewall.service`)
   from the wizard's interface answers.
4. Starts the bridge HTTP server and the dashboard. The native SSH
   lure ships in this tree but has no auto-start systemd unit yet;
   operators run `anglerfish lure serve` themselves (TODO-3).

## Building

The build script runs `lb config` + `lb build` from the Debian
[`live-build`](https://wiki.debian.org/DebianLive) toolchain. It must
run on a Debian/Ubuntu host as root.

```bash
sudo apt install live-build debootstrap squashfs-tools xorriso \
                 isolinux syslinux-common

# Copy the project tree somewhere the chroot can read from:
sudo mkdir -p /tmp/anglerfish-ai
sudo cp -r . /tmp/anglerfish-ai

sudo ./iso/build.sh
```

The ISO is written to `iso/build/anglerfish-ai-<version>.iso` along
with a `.sha256` checksum.

## Verifying

```bash
sha256sum -c anglerfish-ai-<version>.iso.sha256
```

## Booting

The ISO is hybrid — `dd` it to a USB stick or boot it directly in
QEMU/VirtualBox/VMware. On first boot the wizard takes over tty1 and
walks the operator through the responsible-use terms, NIC selection,
Ollama configuration, and secret generation.

## Files in this directory

| Path                                                       | Purpose                                          |
| ---------------------------------------------------------- | ------------------------------------------------ |
| `build.sh`                                                 | Top-level builder                                |
| `auto/config`                                              | `lb config` overrides (distro, arch, bootloader) |
| `auto/clean`                                               | `lb clean` overrides                             |
| `auto/build`                                               | `lb build` overrides + log capture               |
| `config/package-lists/anglerfish.list.chroot`              | Packages installed into the chroot               |
| `config/hooks/normal/0010-anglerfish-user.hook.chroot`     | Creates the `anglerfish` system user             |
| `config/hooks/normal/0020-install-anglerfish.hook.chroot`  | `pip install anglerfish-ai`                      |
| `config/hooks/normal/0050-systemd-units.hook.chroot`       | Copies and enables systemd units                 |
| `config/includes.chroot/etc/anglerfish/`                   | Empty placeholder for runtime config             |
