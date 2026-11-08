"""Discord messages. A fresh webhook object per message, so concurrent
deploys can't post each other's embeds."""

from __future__ import annotations

import logfire
from discord_webhook import DiscordEmbed, DiscordWebhook

from app.settings import NotifySettings

GREEN = "00ff44"
RED = "ff005e"


def discord(settings: NotifySettings, embed: DiscordEmbed) -> None:
    if not settings.discord_webhook_url:
        return
    mention = f"<@{settings.discord_user}>" if settings.discord_user else None
    webhook = DiscordWebhook(
        url=settings.discord_webhook_url,
        content=mention,
        # Only ever ping the owner, whatever ends up in a commit message
        allowed_mentions={"users": [settings.discord_user] if settings.discord_user else []},
    )
    webhook.add_embed(embed)
    try:
        webhook.execute()
    except Exception:
        logfire.error("Failed to post to Discord", _exc_info=True)


def failure(settings: NotifySettings, title: str, error: object, url: str | None = None) -> None:
    # Discord caps embed descriptions at 4096 chars; keep the tail, where errors are
    embed = DiscordEmbed(title=title, description=f"```\n{str(error)[-3500:]}\n```", color=RED)
    if url:
        embed.set_url(url)
    discord(settings, embed)
