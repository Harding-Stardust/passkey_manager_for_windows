r''' 
Passkeys manager inspired by https://github.com/passwordless/webauthn-fido2-key-remover/tree/main

Tranco list over the largest domains: 
wget https://tranco-list.eu/top-1m.csv.zip
rg -o -r $1 "\d+,(.*)" top-1m.csv > top-1m.txt


Basic info:
python passkeys_harding.py

Check sites you have been to:
python passkeys_harding.py --history

Find variant of sites:
python passkeys_harding.py --guess

This will be checking everything, it will take a few minutes but you can go grab a cup of tea
python passkeys_harding.py --domains top-1m.txt --guess --history 

'''

from __future__ import annotations

__version__ = "2026-09-24 16:41:47"
__author__ = "Harding"
__description__ = __doc__
__copyright__ = "Copyright 2026"
__credits__ = ["Other projects"]
__license__ = "GPL"
__maintainer__ = "Harding"
__email__ = "not.at.the.moment@example.com"
__status__ = "Development"

import argparse
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table

G_CONSOLE: Console = Console()

G_KNOWN_DOMAINS: list[str] = [
    # Test and demo sites
    "localhost", "passwordless.dev", "webauthn.io", "webauthn.me", "webauthn.passwordless.id",
    "state-of-passkeys.io", "passkeys.io", "www.passkeys.io", "passkeys.dev", "passkeys.org",
    "passkeys.eu", "passkey.com", "corbado.com", "opotonniee.github.io",
    
    # Big providers
    "google.com", "accounts.google.com", "www.google.com",
    "microsoft.com", "login.microsoft.com", "login.microsoftonline.com", "login.live.com", "live.com",
    "fido.consent.key.microsoft",
    "github.com", "gitlab.com", "amazon.com", "www.amazon.com", "apple.com", "icloud.com",
    "paypal.com", "www.paypal.com", "facebook.com", "twitter.com", "x.com", "linkedin.com",
    "dropbox.com", "cloudflare.com", "dash.cloudflare.com", "shopify.com", "ebay.com", "adobe.com",
    "okta.com", "auth0.com", "1password.com", "bitwarden.com", "proton.me", "account.proton.me", "protonmail.ch"
    "kraken.com", "coinbase.com", "binance.com", "nintendo.com", "sony.com", "playstation.com",
    "steampowered.com", "epicgames.com", "discord.com", "slack.com", "atlassian.com", "id.atlassian.com",
    "twitch.tv", "gnosis.io",
    
    # Swedish
    "bankid.com", "swedbank.se", "handelsbanken.se", "seb.se", "nordea.se", "skatteverket.se",
    "localskills.se",
]  # Extend with your own via --domains

G_GUESS_PREFIXES: list[str] = ["www", "login", "accounts", "id", "auth", "account", "app", "sso"]
G_TWO_PART_TLDS: set[str] = {"co.uk", "org.uk", "ac.uk", "com.au", "co.nz", "co.jp", "com.br", "co.za"}  # Rough eTLD handling

G_FIDO_MARKER: str = "FIDO"
G_FIDO_PREFIX: str = "FIDO_AUTHENTICATOR//"
G_CERTUTIL_LIST_ARGS: list[str] = ["-csp", "NGC", "-key"]
G_CERTUTIL_DELETE_ARGS: list[str] = ["-csp", "NGC", "-delkey"]
G_DELETE_ALL_KEYWORD: str = "all"

G_HISTORY_ALL_KEYWORD: str = "all"
G_HISTORY_FILE_NAME: str = "History"
G_LOGIN_DATA_FILE_NAME: str = "Login Data"
G_FIREFOX_PLACES_FILE_NAME: str = "places.sqlite"
G_SQLITE_SIDECAR_SUFFIXES: list[str] = ["-wal", "-shm"]  # Firefox keeps recent writes in the WAL file

# Browser name, root env var, root path below it, file names to read
G_BROWSER_PROFILE_ROOTS: list[tuple[str, str, str, list[str]]] = [
    ("Chrome", "LOCALAPPDATA", r"Google\Chrome\User Data", [G_HISTORY_FILE_NAME, G_LOGIN_DATA_FILE_NAME]),
    ("Edge", "LOCALAPPDATA", r"Microsoft\Edge\User Data", [G_HISTORY_FILE_NAME, G_LOGIN_DATA_FILE_NAME]),
    ("Brave", "LOCALAPPDATA", r"BraveSoftware\Brave-Browser\User Data", [G_HISTORY_FILE_NAME, G_LOGIN_DATA_FILE_NAME]),
    ("Firefox", "APPDATA", r"Mozilla\Firefox\Profiles", [G_FIREFOX_PLACES_FILE_NAME]),
]


@dataclass
class FidoObject:
    """Represents a WebAuthn credential / FIDO2 key."""
    id: int
    name: str
    rp_id_hash: str
    username_hex: str

    @property
    def username(self) -> str:
        return make_printable(arg_text=hex_to_username(arg_hex=self.username_hex))


def sha256_hex(arg_text: str) -> str:
    """
    Calculates the sha256 hash of a string.

    @param arg_text The text to hash.
    @return The lowercase hex digest.
    """
    return hashlib.sha256(arg_text.encode("utf-8")).hexdigest()


def make_printable(arg_text: str) -> str:
    """
    Replaces non printable characters (control chars) with a visible \\xNN escape,
    so they do not break the table layout.

    @param arg_text The text to sanitize.
    @return The text with control characters escaped.
    """
    l_result: list[str] = []
    for l_char in arg_text:
        if l_char.isprintable():
            l_result.append(l_char)
            continue
        l_result.append(f"\\x{ord(l_char):02x}")  # Show the byte value instead of the raw control char
    return "".join(l_result)


def hex_to_username(arg_hex: str) -> str:
    """
    Decodes a hex string into a UTF-8 username.

    @param arg_hex The hex encoded username.
    @return The decoded username, or the raw hex string if decoding fails.
    """
    try:
        return bytes.fromhex(arg_hex).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return arg_hex  # Fall back to raw hex if it is not valid UTF-8


def get_root_domain(arg_host: str) -> str:
    """
    Roughly derives the registrable domain (eTLD+1) from a host name.
    This is a heuristic without the public suffix list.

    @param arg_host The host name, e.g. login.example.com.
    @return The registrable domain, e.g. example.com.
    """
    l_parts: list[str] = arg_host.split(".")
    if len(l_parts) <= 2: return arg_host
    l_last_two: str = ".".join(l_parts[-2:])
    if l_last_two in G_TWO_PART_TLDS: return ".".join(l_parts[-3:])
    return l_last_two


def expand_guesses(arg_domains: set[str]) -> set[str]:
    """
    Expands a set of domains with the root domain and common subdomain prefixes.

    @param arg_domains The domains to expand.
    @return A new set containing the originals plus all guesses.
    """
    l_result: set[str] = set(arg_domains)
    for l_domain in arg_domains:
        l_root: str = get_root_domain(arg_host=l_domain)
        l_result.add(l_root)
        for l_prefix in G_GUESS_PREFIXES:
            l_result.add(f"{l_prefix}.{l_root}")
    return l_result


def read_domains_file(arg_path: str) -> set[str]:
    """
    Reads a text file with one domain per line.

    @param arg_path The path to the file.
    @return The set of domains, empty if the file is missing.
    """
    l_path: Path = Path(arg_path)
    if not l_path.is_file():
        G_CONSOLE.print(f"[yellow]Domains file not found: {arg_path}[/]")
        return set()
    return {l_line.strip().lower() for l_line in l_path.read_text(encoding="utf-8").splitlines() if l_line.strip()}


def find_history_files_from_path(arg_path: str) -> list[tuple[str, Path]]:
    """
    Finds browser database files from a user supplied path.

    @param arg_path A path to a database file or a profile folder.
    @return A list of (browser name, file path) tuples.
    """
    l_path: Path = Path(arg_path)
    l_wanted_names: set[str] = {G_HISTORY_FILE_NAME, G_LOGIN_DATA_FILE_NAME, G_FIREFOX_PLACES_FILE_NAME}
    if l_path.is_file(): return [("Custom", l_path)]
    if l_path.is_dir(): return [("Custom", l_file) for l_file in l_path.rglob("*") if l_file.name in l_wanted_names and l_file.is_file()]
    G_CONSOLE.print(f"[yellow]History path not found: {arg_path}[/]")
    return []


def find_history_files(arg_history_arg: str) -> list[tuple[str, Path]]:
    """
    Finds browser database files to read.

    @param arg_history_arg Empty string or "all" to auto detect every known browser,
                           otherwise a path to a file or profile folder.
    @return A list of (browser name, file path) tuples.
    """
    l_auto_detect: bool = arg_history_arg == "" or arg_history_arg.lower() == G_HISTORY_ALL_KEYWORD
    if not l_auto_detect: return find_history_files_from_path(arg_path=arg_history_arg)
    l_found: list[tuple[str, Path]] = []
    for l_browser, l_env_var, l_root, l_file_names in G_BROWSER_PROFILE_ROOTS:
        l_base: str | None = os.environ.get(l_env_var)
        if not l_base: continue
        l_root_path: Path = Path(l_base) / l_root
        if not l_root_path.is_dir(): continue
        for l_file in l_root_path.glob("*/*"):
            if l_file.name not in l_file_names: continue
            if not l_file.is_file(): continue
            l_found.append((l_browser, l_file))
    return l_found


def get_hosts_query(arg_file_name: str) -> str:
    """
    Returns the SQL query used to read URLs from a given browser database.

    @param arg_file_name The database file name.
    @return The SQL query.
    """
    if arg_file_name == G_HISTORY_FILE_NAME: return "SELECT url FROM urls"  # Chrome/Edge/Brave history
    if arg_file_name == G_FIREFOX_PLACES_FILE_NAME: return "SELECT url FROM moz_places"  # Firefox history
    return "SELECT origin_url FROM logins"  # Chrome/Edge/Brave saved logins


def read_hosts_from_sqlite(arg_file: Path) -> set[str]:
    """
    Reads host names from a browser database. The file (and any WAL/SHM
    sidecar files) is copied to a temporary location first since the
    browser locks it while running.

    @param arg_file The History, Login Data or places.sqlite file.
    @return A set of lowercase host names.
    """
    l_hosts: set[str] = set()
    l_tmp_dir: str = tempfile.mkdtemp(prefix="passkeys_")
    l_tmp_file: Path = Path(l_tmp_dir) / arg_file.name
    try:
        shutil.copy2(arg_file, l_tmp_file)  # Copy to avoid the browser file lock
        for l_suffix in G_SQLITE_SIDECAR_SUFFIXES:
            l_sidecar: Path = arg_file.with_name(arg_file.name + l_suffix)
            if not l_sidecar.is_file(): continue
            shutil.copy2(l_sidecar, Path(l_tmp_dir) / l_sidecar.name)  # Keeps the most recent visits that are not yet merged
        l_conn: sqlite3.Connection = sqlite3.connect(f"file:{l_tmp_file}?mode=ro", uri=True)
        try:
            for (l_url,) in l_conn.execute(get_hosts_query(arg_file_name=arg_file.name)):
                l_host: str | None = urlparse(l_url).hostname
                if l_host: l_hosts.add(l_host.lower())
        finally:
            l_conn.close()
    except (OSError, sqlite3.Error, ValueError) as l_err:
        G_CONSOLE.print(f"[yellow]Could not read {arg_file}: {l_err}[/]")
    finally:
        shutil.rmtree(l_tmp_dir, ignore_errors=True)
    return l_hosts


def load_history_domains(arg_history_arg: str) -> set[str]:
    """
    Loads all host names from the browser history and saved logins.

    @param arg_history_arg Empty string or "all" to auto detect, or a path to a file or profile folder.
    @return A set of lowercase host names.
    """
    l_files: list[tuple[str, Path]] = find_history_files(arg_history_arg=arg_history_arg)
    if not l_files:
        G_CONSOLE.print("[yellow]No browser history files found.[/]")
        return set()
    l_hosts: set[str] = set()
    l_per_browser: dict[str, int] = {}
    with G_CONSOLE.status("Reading browser history"):
        for l_browser, l_file in l_files:
            l_file_hosts: set[str] = read_hosts_from_sqlite(arg_file=l_file)
            l_hosts |= l_file_hosts
            l_per_browser[l_browser] = l_per_browser.get(l_browser, 0) + len(l_file_hosts)
    for l_browser, l_count in l_per_browser.items():
        G_CONSOLE.print(f"[grey50]{l_browser}: {l_count} hosts[/]")
    G_CONSOLE.print(f"[grey50]Total {len(l_hosts)} unique hosts.[/]")
    return l_hosts


def build_rp_lookup(arg_domains_file: str | None, arg_guess: bool, arg_history: str | None) -> dict[str, str]:
    """
    Builds a sha256 hash to domain lookup from all domain sources.

    @param arg_domains_file Optional path to a file with one domain per line.
    @param arg_guess True to also try common prefixes and root domains.
    @param arg_history None to skip, "all" to auto detect, or a path to a history file or folder.
    @return A dict mapping sha256 RP ID hashes to domain names.
    """
    l_domains: set[str] = set(G_KNOWN_DOMAINS)
    if arg_domains_file: l_domains |= read_domains_file(arg_path=arg_domains_file)
    if arg_history is not None: l_domains |= load_history_domains(arg_history_arg=arg_history)
    if arg_guess: l_domains = expand_guesses(arg_domains=l_domains)
    l_lookup: dict[str, str] = {}
    for l_domain in sorted(l_domains):  # Sorted so the result is deterministic
        l_lookup.setdefault(sha256_hex(arg_text=l_domain), l_domain)
    G_CONSOLE.print(f"[grey50]Hashed {len(l_lookup)} candidate domains.[/]")
    return l_lookup


def run_certutil(arg_args: list[str]) -> tuple[str, str]:
    """
    Runs certutil with the given arguments and captures the output.

    @param arg_args The arguments to pass to certutil.
    @return A tuple of (stdout, stderr).
    """
    l_result: subprocess.CompletedProcess[str] = subprocess.run(
        ["certutil", *arg_args],
        capture_output=True,
        text=True,
        check=False,  # Do not raise on non-zero exit codes
    )
    return l_result.stdout, l_result.stderr


def parse_keys(arg_key_string: str) -> list[FidoObject]:
    """
    Parses the certutil key listing into FidoObject instances.

    @param arg_key_string The raw stdout from certutil.
    @return A list of parsed FIDO keys.
    """
    l_keys: list[FidoObject] = []
    for l_line in arg_key_string.splitlines():
        if G_FIDO_MARKER not in l_line: continue
        if G_FIDO_PREFIX not in l_line: continue
        l_details: str = l_line.split(G_FIDO_PREFIX)[1]  # Everything after the prefix
        l_parts: list[str] = l_details.split("_")
        if len(l_parts) < 2: continue
        l_keys.append(FidoObject(
            id=len(l_keys) + 1,
            name=l_line.strip(),
            rp_id_hash=l_parts[0],
            username_hex=l_parts[1],
        ))
    return l_keys


def load_keys() -> list[FidoObject]:
    """
    Loads all FIDO keys using certutil.

    @return A list of parsed FIDO keys.
    """
    with G_CONSOLE.status("Loading fido2 keys"):
        l_key_string, _l_error = run_certutil(arg_args=G_CERTUTIL_LIST_ARGS)
    return parse_keys(arg_key_string=l_key_string)


def print_keys(arg_keys: list[FidoObject], arg_rp_lookup: dict[str, str]) -> None:
    """
    Prints all keys in a table.

    @param arg_keys The keys to print.
    @param arg_rp_lookup A dict mapping sha256 RP ID hashes to domain names.
    """
    l_table: Table = Table(show_lines=False)
    l_table.add_column("Id", justify="right", style="bold")
    l_table.add_column("Username", style="cyan", overflow="fold")
    l_table.add_column("RP", style="yellow")
    l_table.add_column("sha256 RP ID", style="grey50", overflow="fold")
    for l_key in arg_keys:
        l_rp: str = arg_rp_lookup.get(l_key.rp_id_hash, "?")  # ? for unknown relying parties
        l_table.add_row(str(l_key.id), escape(l_key.username), escape(l_rp), l_key.rp_id_hash)
    G_CONSOLE.print(l_table)
    l_unknown: int = len({l_key.rp_id_hash for l_key in arg_keys if l_key.rp_id_hash not in arg_rp_lookup})
    if l_unknown > 0:
        G_CONSOLE.print(f"[yellow]{l_unknown} unknown RP ID hash(es). Try --guess, --history or --domains FILE.[/]")


def resolve_delete_ids(arg_keys: list[FidoObject], arg_ids: list[str]) -> list[FidoObject] | None:
    """
    Resolves the ids given to --delete into keys.

    @param arg_keys The full list of parsed keys.
    @param arg_ids The raw ids from the command line, or ["all"].
    @return The keys to delete, or None if any id is invalid.
    """
    if [l_id.lower() for l_id in arg_ids] == [G_DELETE_ALL_KEYWORD]: return arg_keys
    l_valid_ids: set[int] = {l_key.id for l_key in arg_keys}
    l_wanted: list[int] = []
    for l_raw in arg_ids:
        if not l_raw.isdigit():
            G_CONSOLE.print(f"[red]Invalid id: {l_raw}[/]")
            return None
        if int(l_raw) not in l_valid_ids:
            G_CONSOLE.print(f"[red]No key with id: {l_raw}[/]")
            return None
        l_wanted.append(int(l_raw))
    return [l_key for l_key in arg_keys if l_key.id in l_wanted]


def delete_keys(arg_keys: list[FidoObject]) -> None:
    """
    Deletes the given keys using certutil.

    @param arg_keys The keys to delete.
    """
    for l_key in arg_keys:
        G_CONSOLE.print(Rule(f"[red]Deleting... [/]{l_key.id}. {escape(l_key.username)}", align="left"))
        G_CONSOLE.print(f"certutil -csp NGC -delkey {l_key.name}", style="grey50", markup=False, highlight=False)
        l_res, _l_error = run_certutil(arg_args=[*G_CERTUTIL_DELETE_ARGS, l_key.name])
        G_CONSOLE.print(l_res, style="grey50", markup=False, highlight=False)


def parse_args() -> argparse.Namespace:
    """
    Parses the command line arguments.

    @return The parsed arguments.
    """
    l_parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="List and remove Windows 10 WebAuthn / FIDO2 keys. Run without arguments to list all keys."
    )
    l_parser.add_argument(
        "--delete",
        nargs="+",
        metavar="ID",
        help="Ids of the keys to delete (as shown in the list), or 'all' to delete every key. Requires administrator.",
    )
    l_parser.add_argument(
        "--domains",
        metavar="FILE",
        help="Text file with one domain per line, used to identify RP ID hashes.",
    )
    l_parser.add_argument(
        "--guess",
        action="store_true",
        help="Also try the root domain and common prefixes (www, login, accounts, id, auth, account, app, sso) on every candidate domain.",
    )
    l_parser.add_argument(
        "--history",
        nargs="?",
        const=G_HISTORY_ALL_KEYWORD,
        default=None,
        metavar="all|PATH",
        help="Use hosts from browser history and saved logins. 'all' (or no value) auto detects Chrome, Edge, Brave and Firefox. "
             "Otherwise pass a History or places.sqlite file, or a profile folder.",
    )
    return l_parser.parse_args()


def main() -> None:
    l_args: argparse.Namespace = parse_args()
    l_rp_lookup: dict[str, str] = build_rp_lookup(
        arg_domains_file=l_args.domains,
        arg_guess=l_args.guess,
        arg_history=l_args.history,
    )
    l_keys: list[FidoObject] = load_keys()
    G_CONSOLE.print(f"[bold]Found {len(l_keys)} keys.[/]")
    if not l_keys: return

    # No --delete flag, just list the keys
    if l_args.delete is None:
        print_keys(arg_keys=l_keys, arg_rp_lookup=l_rp_lookup)
        G_CONSOLE.print("\nRun again with [bold]--delete <id> [<id> ...][/] or [bold]--delete all[/] to remove keys.")
        G_CONSOLE.print("[bold]Note:[/] Deleting requires an administrator shell.")
        return

    l_to_delete: list[FidoObject] | None = resolve_delete_ids(arg_keys=l_keys, arg_ids=l_args.delete)
    if l_to_delete is None: return
    delete_keys(arg_keys=l_to_delete)


if __name__ == "__main__":
    if sys.platform != "win32":
        G_CONSOLE.print("[red]This tool only works on Windows (certutil is required).[/]")
        sys.exit(1)
    main()