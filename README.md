# av-remove

Find and remove third-party / OEM antivirus from a Windows PC, then confirm
**Microsoft Defender** has taken over. Built for the trialware that ships on new
machines (McAfee, Norton) and the free AVs customers pick up.

Served via Cloudflare Pages at **https://avremove.nerdyneighbor.net**.

## Run it (elevated Windows PowerShell)

```powershell
irm avremove.nerdyneighbor.net | iex
```

Options (set before the irm line):

```powershell
$env:NN_AV     = 'scan'    # only LIST what's installed, remove nothing
$env:NN_REBOOT = 'yes'     # restart at the end if needed ('no' = never)
irm avremove.nerdyneighbor.net | iex
```

Also available in the menu: `irm toolkit.nerdyneighbor.net | iex`.

## What it does

1. **Scans first, always.** It reads every uninstall entry (both 32/64-bit views
   and per-user installs) and lists **every component** each vendor left behind.
   Norton in particular installs many separate programs (360, Secure VPN,
   Password Manager, Utilities, AntiTrack, Safe Web, Genie) - each shows up on
   its own line, tagged `[silent]` or `[manual]`. It also prints what the Windows
   Security Center thinks is installed.
2. **Removes each component with its own uninstaller**, in this order:
   - the vendor's **registered quiet uninstall command** (`QuietUninstallString`), if there is one;
   - a standard **MSI silent uninstall** (`msiexec /x {GUID} /qn /norestart`) for MSI-based products;
   - a small set of **documented unattended switches** (Avira `/remsilentnoreboot`, TotalAV/AVG/Avast `/S`).

   If there's no documented silent path, behavior depends on who's running it:
   when a **tech is at the keyboard**, it launches the vendor's own uninstaller
   with its window visible so the tech clicks through; from the **RMM (SYSTEM)**
   it just lists it, since a UI uninstaller would hang unattended. Either way,
   anything it can't finish is reported so it can be cleared with the vendor tool.
3. **Confirms Defender** with `Get-MpComputerStatus` and refreshes its
   definitions once it's active.

Malwarebytes is never touched. Logs to `C:\ProgramData\NerdyNeighbor\avremove.log`.

## Vendor removal tools (the [manual] fallback)

Some vendors ship no silent uninstall. Download their official tool and run it,
then re-run this script:

| Vendor | Tool | Notes |
|---|---|---|
| McAfee | [MCPR.exe](https://download.mcafee.com/molbin/iss-loc/SupportTools/MCPR/MCPR.exe) | Reboot after |
| Norton | [Norton Remover](https://www.norton.com/nortonremover) | "Remove only", then restart |
| Avast | [Avast Clear](https://honzik.avcdn.net/setup/avast-av/release/avast_av_clear.exe) | Prompts for Safe Mode |
| AVG | [AVG Clear](https://honzik.avcdn.net/setup/avg-av/release/avg_av_clear.exe) | Prompts for Safe Mode |
| Kaspersky | [kavremover](https://media.kaspersky.com/utilities/ConsumerUtilities/kavremvr.exe) | Asks for a CAPTCHA - not silent |
| Bitdefender | [Uninstall Tool](https://www.bitdefender.com/links/uninstall_consumer_paid.html) | Turn off password + Shield first |
| ESET | [ESET Uninstaller](https://download.eset.com/com/eset/tools/installers/eset_apps_remover/latest/uninstaller.exe) | Runs in Safe Mode (`/force`) |
| Panda | [Panda Uninstaller](https://www.pandasecurity.com/resources/tools/uninstaller.exe) | Reboots at end |

Sophos Home needs Tamper Protection turned off from the Sophos Home dashboard,
and PC Matic needs an uninstaller token from the customer's PC Matic console -
neither can be removed unattended.

## Caveats

- Most AV only finishes removing **after a restart**. Run this again afterward:
  it re-scans, clears leftovers, and re-checks Defender.
- Run from SuperOps (SYSTEM), it removes everything with a silent path and lists
  the rest in the log; it never reboots unless `NN_REBOOT='yes'`.
- Deep leftovers (locked drivers, PUP watchdogs) are out of scope - use
  Malwarebytes in Safe Mode for those.
