import json
import os
import re
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
STATE_FILE = "seen_bounties.json"
MAX_COMMENTS = 20        # Skip overcrowded / heavily-contested threads
MAX_AGE_DAYS = 30        # HARD age gate: old bounties = dead payout rail / dormant funder
PER_PAGE = 30
DRY_RUN = bool(os.environ.get("DRY_RUN"))  # Print candidates only; no notify, no state write

# Fiat-paying bounty searches (Algora tags issues with a "💎 Bounty" label + a "$N" label).
# We deliberately DO NOT do a bare "bounty" search — it is dominated by token/web3 farms.
# Exclude the worst known farm accounts at the query level so the recency-sorted result
# window isn't consumed by their bursts, leaving room for real bounties.
EXCLUDE_USERS = " ".join(f"-user:{u}" for u in [
    "SecureBananaLabs", "UnsafeLabs", "Scottcjn", "ramimbo",
    "ClankerNation", "boundlessfi", "orchestration-agent", "archestra-ai",
])
SEARCH_QUERIES = [
    f'is:issue is:open label:"💎 Bounty" {EXCLUDE_USERS} sort:created-desc',
    f'is:issue is:open label:"💵 Bounty" {EXCLUDE_USERS} sort:created-desc',
    f'is:issue is:open label:"💰 Bounty" {EXCLUDE_USERS} sort:created-desc',
]
MAX_PER_REPO = 2         # Don't let one repo's burst dominate a single alert

# Crypto / web3 / token-farm / AI-agent-farm / content-spam terms (word-boundary matched).
# Short ambiguous tokens (eth, sol, dao, rtc, token) are intentionally excluded to avoid
# false positives on legitimate bounties (e.g. "JWT token", "solution").
DENY_TERMS = [
    "crypto", "cryptocurrency", "web3", "blockchain", "on-chain", "onchain",
    "airdrop", "staking", "memecoin", "stablecoin", "faucet", "presale",
    "solana", "ethereum", "polygon", "arbitrum", "defi", "nft", "smart contract",
    "rustchain", "clanker", "ai agent", "agentic", "swarm intelligence",
    "play to earn", "p2e", "casino", "gambling", "trading bot",
    "article writing", "blog post", "content creator", "referral program",
]
DENY_TERMS_RE = re.compile(r"\b(" + "|".join(re.escape(t) for t in DENY_TERMS) + r")\b")

# Known bounty-farm orgs/repos (substring match on "owner/repo").
DENY_REPOS = [
    "rustchain", "mergework", "clankernation", "openagents", "boundlessfi",
    "spectral-finance", "securebananalabs", "unsafelabs", "stellar-bounty",
    "orchestration-agent", "agentorchestration", "manus-artifacts", "warpspeed",
    "mergeos", "bounty-autopilot", "misakanet", "boundless", "ai-agent-pay",
    "archestra",  # interview-gated + honeypot-laden (not open to outside hunters)
]

# Hiring-funnel labels/notes that mean the bounty is not open to outside hunters.
INTERVIEW_GATE = ["reserved for se interview", "reserved for candidates", "interview process"]


def load_seen_bounties():
    """Load previously seen bounty URLs from the state file."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return set(data)
        except Exception as e:
            print(f"Error loading state file: {e}")
    return set()


def save_seen_bounties(seen_urls):
    """Save the updated list of seen bounty URLs."""
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(seen_urls), f, indent=2)
    except Exception as e:
        print(f"Error saving state file: {e}")


def search_github(query, token=None):
    """Fetch search results from the GitHub Issues Search API."""
    url = f"https://api.github.com/search/issues?{urllib.parse.urlencode({'q': query, 'per_page': PER_PAGE})}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BountyScout",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"GitHub Search API Error for query '{query}': {e}")
        return {}


def _label_names(item):
    return [str(l.get("name", "")).lower() for l in item.get("labels", []) if isinstance(l, dict)]


def fiat_amount(item):
    """Return a detected USD bounty amount like '$500' from labels or title, else None."""
    for name in _label_names(item):
        m = re.search(r"\$\s?([0-9][0-9,]*)", name)
        if m:
            return "$" + m.group(1)
    m = re.search(r"\$\s?([0-9][0-9,]*)", str(item.get("title", "")))
    return ("$" + m.group(1)) if m else None


def age_days(item):
    """Days since the issue was created, or None if unknown."""
    created = item.get("created_at")
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def evaluate(item):
    """Return (amount, age) if this is a clean, fresh, fiat bounty open to outside hunters; else None."""
    if "pull_request" in item:
        return None
    if item.get("assignees"):
        return None
    if int(item.get("comments", 0)) > MAX_COMMENTS:
        return None

    age = age_days(item)
    if age is None or age > MAX_AGE_DAYS:
        return None

    amount = fiat_amount(item)
    if not amount:  # Require a real USD amount — kills token-only farms
        return None

    repo = str(item.get("repository_url", "")).lower() + " " + str(item.get("html_url", "")).lower()
    if any(bad in repo for bad in DENY_REPOS):
        return None

    haystack = " ".join([
        str(item.get("title", "")),
        str(item.get("body", "") or "")[:2000],
        " ".join(_label_names(item)),
    ]).lower()
    if DENY_TERMS_RE.search(haystack):
        return None
    if any(g in haystack for g in INTERVIEW_GATE):
        return None

    return amount, age


def send_telegram_notification(token, chat_id, message):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown", "disable_web_page_preview": False}
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            print("Telegram notification sent successfully.")
    except Exception as e:
        print(f"Failed to send Telegram notification: {e}")


def send_discord_notification(webhook_url, message):
    req = urllib.request.Request(webhook_url, data=json.dumps({"content": message}).encode("utf-8"),
                                headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            print("Discord notification sent successfully.")
    except Exception as e:
        print(f"Failed to send Discord notification: {e}")


def create_github_issue(repo_fullname, token, title, body):
    """Create an issue in the host repository to trigger a native GitHub alert."""
    url = f"https://api.github.com/repos/{repo_fullname}/issues"
    payload = {"title": title, "body": body, "labels": ["bounty-alert"]}
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BountyScout",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {token}",
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15):
            print("GitHub Issue notification created successfully.")
    except Exception as e:
        print(f"Failed to create GitHub Issue notification: {e}")


def main():
    github_token = os.environ.get("GITHUB_TOKEN")
    repo_fullname = os.environ.get("GITHUB_REPOSITORY")
    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    discord_webhook = os.environ.get("DISCORD_WEBHOOK_URL")

    seen_urls = load_seen_bounties()
    new_bounties = []
    repo_counts = {}

    print("Scouting GitHub for fresh, fiat-paying bounties...")
    for query in SEARCH_QUERIES:
        results = search_github(query, github_token)
        for item in results.get("items", []):
            url = item.get("html_url")
            if not url or url in seen_urls:
                continue
            verdict = evaluate(item)
            if verdict:
                amount, age = verdict
                repo = url.split("/issues/")[0].replace("https://github.com/", "")
                seen_urls.add(url)  # mark seen regardless, so farms don't re-flood next run
                if repo_counts.get(repo, 0) >= MAX_PER_REPO:
                    continue
                repo_counts[repo] = repo_counts.get(repo, 0) + 1
                new_bounties.append({
                    "title": item.get("title"),
                    "url": url,
                    "repo": repo,
                    "amount": amount,
                    "age_days": age,
                    "comments": item.get("comments"),
                })

    if not new_bounties:
        print("No new fiat bounty opportunities found.")
        return

    new_bounties.sort(key=lambda b: b["age_days"])  # freshest first
    print(f"Discovered {len(new_bounties)} NEW fiat bounty opportunities!")
    for b in new_bounties:
        print(f"  {b['amount']:>7}  {b['age_days']:>2}d  c{b['comments']:<3} {b['repo']}  {b['url']}")

    if DRY_RUN:
        print("\n[DRY_RUN] No notifications sent, state not saved.")
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    notif_lines = [
        f"🎯 *New Bounty Alert* ({now_str})",
        f"Found {len(new_bounties)} fresh fiat {'bounties' if len(new_bounties) > 1 else 'bounty'}:\n",
    ]
    for idx, b in enumerate(new_bounties, start=1):
        notif_lines.append(f"{idx}. *{b['title']}* — {b['amount']}")
        notif_lines.append(f"   • Repo: `{b['repo']}`  ({b['age_days']}d old, {b['comments']} comments)")
        notif_lines.append(f"   • {b['url']}\n")
    notification_msg = "\n".join(notif_lines)

    if telegram_token and telegram_chat_id:
        send_telegram_notification(telegram_token, telegram_chat_id, notification_msg)

    if discord_webhook:
        send_discord_notification(discord_webhook, notification_msg.replace("•", "-"))

    if github_token and repo_fullname:
        issue_title = f"🎯 Bounty Alert: {len(new_bounties)} fresh fiat {'bounties' if len(new_bounties) > 1 else 'bounty'}"
        issue_body = f"### Fresh fiat-paying bounties (≤{MAX_AGE_DAYS}d old, ≤{MAX_COMMENTS} comments, unassigned)\n\n**Scan:** {now_str}\n\n"
        for idx, b in enumerate(new_bounties, start=1):
            issue_body += (
                f"#### {idx}. [{b['title']}]({b['url']}) — **{b['amount']}**\n"
                f"- Repo: [{b['repo']}](https://github.com/{b['repo']}) · {b['age_days']}d old · {b['comments']} comments\n\n"
            )
        create_github_issue(repo_fullname, github_token, issue_title, issue_body)

    save_seen_bounties(seen_urls)
    print("State saved successfully.")


if __name__ == "__main__":
    main()
