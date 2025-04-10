from django.db import models
from django.contrib.auth.models import User  # Import the User model
from django.utils import timezone

# Create your models here.
class SearchQuery(models.Model):
    INDICATOR_TYPES = (
        ('email', 'Email'),
        ('hash', 'Hash'),
        ('url', 'URL'),
        ('domain', 'Domain'),
        ('ip', 'IP'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    query = models.CharField(max_length=255)
    module_used = models.CharField(max_length=100)
    result_count = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    indicator = models.CharField(max_length=255, null=True, blank=True)
    indicator_type = models.CharField(max_length=10, choices=INDICATOR_TYPES)
    modules_applied = models.JSONField(default=list)  # List of modules that were used
    results = models.JSONField(default=dict)  # Store results as a dict (you can extend it with custom data)
    last_updated_at = models.DateTimeField(auto_now=True)  # Timestamp of the last update

    def __str__(self):
        return f"Search: {self.query} by {self.user.username}"


class Module(models.Model):
    name = models.CharField(max_length=100, unique=True)  # Name of the module (e.g., VirusTotal)
    description = models.TextField()  # Description of the module
    enabled = models.BooleanField(default=True)  # Whether the module is enabled for the user
    created_at = models.DateTimeField(default=timezone.now)  # When the module was created

    def __str__(self):
        return self.name

class UserModule(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    module = models.ForeignKey(Module, on_delete=models.CASCADE, null=True, blank=True)
    enabled = models.BooleanField(default=True)  # Whether the module is enabled for this user
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.module.name} ({'Enabled' if self.enabled else 'Disabled'})"