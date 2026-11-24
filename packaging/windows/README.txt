Rerun (alpha) - by Mythen Studios
=================================

Rerun detects old PC games on Steam and applies the compatibility fixes they need, and
removes them again just as cleanly. This is an UNSIGNED ALPHA built by the developer for his
own use. It is not a release.

What is in this folder
----------------------
  rerun-app.exe            the app (start this one)
  rerun.exe                the command line (also used by the scripts below)
  rerun-launch.exe         the start shim Steam runs when a game has Rerun's launch option
  index.json, .sig         the signed Topo index (missing in a test build without index)
  install.ps1              installs Rerun for this Windows account (no administrator)
  uninstall.ps1            removes Rerun again
  payload.json             the list of these files with their SHA-256
  LICENSE, THIRD-PARTY-NOTICES.txt

Rerun runs without administrator rights. Nothing runs in the background: no service, no tray
icon, no autostart. Firewall fixes are not available in this alpha (they need the separately
installed helper, which the alpha does not ship).

Unsigned: Smart App Control
---------------------------
The programs are not code-signed yet. Smart App Control may block one of them at any time
(Windows says so; the scripts report "os error 4551"). The scripts never try to get around
it: they stop and undo what they did. Without Smart App Control, Windows SmartScreen may ask
once.

Install (per user, no administrator)
------------------------------------
In a normal (not administrator) PowerShell window, from this folder:

  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

It shows every file it copies (with its SHA-256), the Start-menu shortcut and the index it
imports, then waits for one Enter (close the window to cancel). It installs to

  %LOCALAPPDATA%\Programs\Rerun

(a fixed folder: Steam's launch options name it, so it never moves), creates the Start-menu
shortcut "Rerun", and imports the signed index. Rerun keeps its own data (journal, backups,
launch profiles, downloaded packages, settings) in %LOCALAPPDATA%\Rerun.

Portable (no install)
---------------------
Unpack the zip anywhere and start rerun-app.exe. Import the index once:

  .\rerun.exe index import .\index.json .\index.json.sig

Steam launch options that Rerun offers name the folder rerun-launch.exe is in. If you move or
delete a portable folder, games with such an option no longer start until you paste the new
option (shown on the "Applied" page) or remove it in Steam.

Uninstall
---------
First undo the fixes you applied, in Rerun: the uninstaller refuses while a change is open,
since it would delete the journal and the backups an undo needs (with -KeepData it goes on
and keeps them for the next install). Then, in a normal PowerShell window:

  powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\Rerun\uninstall.ps1"

(for a portable copy: the uninstall.ps1 in its folder). It lists open changes and stops, or
shows what it removes: the program files, the Start-menu shortcut and Rerun's data folder
%LOCALAPPDATA%\Rerun with its size, then waits for one Enter. Add -KeepData to keep the data
folder. All copies share that data folder: removing a portable copy keeps it while Rerun is
also installed. Close every Rerun window first. It warns about games Steam may still start through rerun-launch.exe: remove their
launch option in Steam (Properties > General > Launch options), Rerun never edits Steam's
settings. It never touches Steam, a game folder, or anything outside these paths.

Update
------
Uninstall with -KeepData, then install the new version:

  powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\Rerun\uninstall.ps1" -KeepData
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

Open changes stay recorded in the data folder and can be undone by the new version. The
install folder stays the same, so the launch options in Steam keep working.

Source and licence: https://github.com/mythenstudios/rerun (GPL-3.0-or-later).
