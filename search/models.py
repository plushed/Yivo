from django.db import models
from django.contrib.auth.models import User  # Import the User model
from django.utils import timezone
from search.utils import normalize_module_name

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
    result_count = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    indicator = models.CharField(max_length=255, null=True, blank=True)
    indicator_type = models.CharField(max_length=10, choices=INDICATOR_TYPES)
    modules_applied = models.JSONField(default=list)  # List of modules that were used
    results = models.JSONField(default=dict)  # Store results as a dict (you can extend it with custom data)
    last_updated_at = models.DateTimeField(auto_now=True)  # Timestamp of the last update
    risk_score = models.FloatField(default=0)  # Add this field to store the risk score

    def __str__(self):
        return f"Search: {self.query} by {self.user.username}"

    def save_search_query(user, query_data):
        search_query = SearchQuery.objects.create(
            user=user,
            query=query_data["query"],
            module_used=query_data["module_used"],
            result_count=query_data["result_count"],
            indicator=query_data["indicator"],
            indicator_type=query_data["indicator_type"],
            modules_applied=query_data["modules_applied"],
            results=query_data["results"]
        )
        search_query.calculate_risk_score()  # Calculate and save the risk score
        return search_query

class IndicatorType(models.Model):
    name = models.CharField(max_length=50, unique=True)  # E.g., Hash, URL, Domain, IP
    description = models.TextField(blank=True, null=True)  # Optional description of the indicator type

    def __str__(self):
        return self.name

class Module(models.Model):
    FEED_TYPE_CHOICES = [
    ("api", "API Connected"),
    ("builtin", "Built-in"),
]
    name = models.CharField(max_length=100, unique=True)  # Name of the module (e.g., VirusTotal)
    description = models.TextField()  # Description of the module
    website = models.URLField(max_length=200, blank=True, null=True)  # URL of the module's website
    enabled = models.BooleanField(default=True)  # Whether the module is enabled for the user
    created_at = models.DateTimeField(default=timezone.now)  # When the module was created
    indicator_types = models.ManyToManyField(IndicatorType, related_name="modules", blank=True)  # Indicator types supported by the module
    default_weight = models.DecimalField(max_digits=5, decimal_places=2, default=1.0)  # Default weight
    type = models.CharField(max_length=10, choices=FEED_TYPE_CHOICES, default="api")


    def __str__(self):
        return self.name

class UserModule(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    module = models.ForeignKey(Module, null=True, blank=True, on_delete=models.CASCADE)
    enabled = models.BooleanField(default=True)
    api_key = models.CharField(max_length=255, null=True, blank=True)  # API key for the module
    api_secret = models.CharField(max_length=255, null=True, blank=True)  # API secret for the module
    created_at = models.DateTimeField(default=timezone.now)
    weight = models.DecimalField(max_digits=5, decimal_places=2, default=1.0)  # User-specific weight

    def __str__(self):
        return f"{self.user.username} - {self.module.name} ({'Enabled' if self.enabled else 'Disabled'})"
