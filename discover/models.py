from django.db import models
from django.contrib.auth.models import User  # Import the User model
from django.utils import timezone

# Create your models here.
class RSSFeed(models.Model):
    FEED_TYPE_CHOICES = [
        ("builtin", "Built-in"),
        ("custom", "Custom"),
    ]
    name = models.CharField(max_length=150, unique=True)
    url = models.URLField(max_length=300)
    type = models.CharField(max_length=10, choices=FEED_TYPE_CHOICES, default="builtin")
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name

class UserRSSFeed(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rss_feed = models.ForeignKey(RSSFeed, null=True, blank=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=150)  # For custom feeds (user can rename)
    url = models.URLField(max_length=300)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.name} ({'Enabled' if self.enabled else 'Disabled'})"