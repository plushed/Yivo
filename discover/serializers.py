from rest_framework import serializers
from .models import RSSFeed, UserRSSFeed

class RSSFeedSerializer(serializers.ModelSerializer):
    class Meta:
        model = RSSFeed
        fields = ['id', 'name', 'url', 'type']

class UserRSSFeedSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRSSFeed
        fields = ['id', 'name', 'url', 'enabled', 'rss_feed', 'created_at']