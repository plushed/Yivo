from django.urls import path
from .views import RSSFeedsSettingsView, RSSFeedArticlesView


urlpatterns = [
    path('feeds/rss/settings/', RSSFeedsSettingsView.as_view(), name='rss-feeds-settings'),
    path('feeds/rss/articles/', RSSFeedArticlesView.as_view(), name='rss-feed-articles'),
]
