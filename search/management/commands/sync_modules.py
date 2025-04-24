from django.core.management.base import BaseCommand
from django.utils.text import slugify
from search.models import Module, IndicatorType
from search.dispatch_table import MODULE_QUERIES  # import your dispatch map here

class Command(BaseCommand):
    help = 'Syncs the MODULE_QUERIES dispatch table to the database'

    def handle(self, *args, **kwargs):
        existing_modules = Module.objects.values_list('name', flat=True)

        for name, meta in MODULE_QUERIES.items():
            description = meta.get('description', '')
            weight = meta.get('default_weight', 1.0)
            supported_types = meta.get('supported_types', [])
            website = meta.get('website', '')  # Get website URL from the MODULE_QUERIES if available

            # Create or update the module
            module, created = Module.objects.update_or_create(
                name=name,
                defaults={
                    'description': description,
                    'default_weight': weight,
                    'website': website,  # Add website field dynamically from MODULE_QUERIES
                    'type': meta.get('type', 'api'),
                }
            )

            # Link IndicatorTypes
            indicator_objs = []
            for itype in supported_types:
                # Normalize and create if missing
                label = itype.capitalize()
                indicator_type, _ = IndicatorType.objects.get_or_create(name=label)
                indicator_objs.append(indicator_type)

            module.indicator_types.set(indicator_objs)
            module.save()

            action = "Created" if created else "Updated"
            self.stdout.write(f"{action} module: {name}")

        self.stdout.write(self.style.SUCCESS("Module sync complete."))

        # Remove stale modules that are no longer in the dispatch table
        dispatch_names = set(MODULE_QUERIES.keys())
        stale_modules = Module.objects.exclude(name__in=dispatch_names)
        count = stale_modules.count()
        if count:
            stale_modules.delete()
            self.stdout.write(f"Removed {count} stale modules.")
