from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import RSSFeed, UserRSSFeed
from .serializers import UserRSSFeedSerializer, RSSFeedSerializer
from rest_framework.response import Response
import feedparser


# Create your views here.
class RSSFeedsSettingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # Built-in feeds
        builtin_feeds = RSSFeed.objects.all()
        user_feeds = UserRSSFeed.objects.filter(user=user)

        # Map builtin feeds to user settings (if any)
        builtin_result = {}
        for feed in builtin_feeds:
            matching_user_feed = user_feeds.filter(rss_feed=feed).first()
            builtin_result[feed.name] = {
                "enabled": matching_user_feed.enabled if matching_user_feed else True,
                "url": feed.url,
            }

        # Custom feeds
        custom_result = []
        for feed in user_feeds.filter(rss_feed__isnull=True):
            custom_result.append({
                "name": feed.name,
                "url": feed.url,
                "enabled": feed.enabled,
            })

        return Response({
            "builtin": builtin_result,
            "custom": custom_result,
        })

    def post(self, request):
        user = request.user
        data = request.data

        builtin = data.get("builtin", {})
        custom = data.get("custom", [])

        # Update built-in feeds
        for feed_name, feed_info in builtin.items():
            try:
                feed_obj = RSSFeed.objects.get(name=feed_name)
                user_feed, created = UserRSSFeed.objects.get_or_create(
                    user=user, rss_feed=feed_obj,
                    defaults={"name": feed_obj.name, "url": feed_obj.url}
                )
                user_feed.enabled = feed_info.get("enabled", True)
                user_feed.save()
            except RSSFeed.DoesNotExist:
                continue

        # Clear and re-create custom feeds
        UserRSSFeed.objects.filter(user=user, rss_feed__isnull=True).delete()
        for custom_feed in custom:
            UserRSSFeed.objects.create(
                user=user,
                name=custom_feed.get("name", ""),
                url=custom_feed.get("url", ""),
                enabled=custom_feed.get("enabled", True),
            )

        return Response({"message": "RSS Feed settings saved successfully."})

class RSSFeedArticlesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # Get user's enabled feeds (both built-in and custom)
        enabled_feeds = UserRSSFeed.objects.filter(user=user, enabled=True)

        articles = []

        for user_feed in enabled_feeds:
            feed_data = feedparser.parse(user_feed.url)

            # Grab top 5 articles from each feed
            for entry in feed_data.entries[:5]:
                articles.append({
                    "feed_name": user_feed.name,
                    "title": entry.get("title", "No Title"),
                    "link": entry.get("link", "#"),
                    "summary": entry.get("summary", "")[:500],  # truncate summary if too long
                    "published": entry.get("published", None),
                })

        # Optional: Sort articles by published date if available
        articles.sort(key=lambda x: x.get("published", ""), reverse=True)

        return Response({"articles": articles})
