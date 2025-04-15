from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import SearchQuery, Module, UserModule
from .serializers import SearchQuerySerializer
from rest_framework.permissions import IsAuthenticated
from .serializers import ModuleSerializer
from .dispatch_table import MODULE_QUERIES
import re
from django.core.exceptions import ValidationError
from .query_router import route_query
import logging

# Set up logging for debugging
logger = logging.getLogger(__name__)

class SearchQueryView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        indicator = request.data.get('indicator')
        indicator_type = request.data.get('indicator_type')

        # Log the incoming data
        logger.debug(f"Received request with indicator: {indicator}, indicator_type: {indicator_type}")

        if not indicator or not indicator_type:
            return Response({"detail": "Indicator and indicator_type are required."}, status=400)

        # Validate the indicator based on the type
        validation_error = self.validate_indicator(indicator, indicator_type)
        if validation_error:
            return Response({"detail": validation_error}, status=400)

        # Get the list of enabled modules for the user
        enabled_modules = [um.module.name for um in UserModule.objects.filter(user=request.user, enabled=True)]
        
        # Log enabled modules for debugging
        logger.debug(f"Enabled modules for user: {enabled_modules}")
        
        # Filter the modules that support the given indicator type
        applicable_modules = [
            module for module in enabled_modules
            if module in MODULE_QUERIES and indicator_type in MODULE_QUERIES[module]['supported_types']
        ]

        # Log the applicable modules
        logger.debug(f"Applicable modules: {applicable_modules}")

        # If no modules support the indicator type, return an error
        if not applicable_modules:
            return Response({"detail": "No enabled modules support the given indicator type."}, status=400)

        # Get the query results from the selected modules
        logger.debug(f"Calling route_query with indicator: {indicator}, indicator_type: {indicator_type}, modules: {applicable_modules}")
        results = route_query(request.user, indicator, indicator_type, applicable_modules)

        # Log the results
        logger.debug(f"Query results: {results}")

        # Save the search query and the risk score in the database
        search_query = SearchQuery.objects.create(
            user=request.user,
            indicator=indicator,
            indicator_type=indicator_type,
            results=results,  # Assuming results are saved as a JSON field or similar
        )

        return Response({
            "results": results,
        }, status=200)


    def validate_indicator(self, indicator, indicator_type):
        # Validate based on type
        if indicator_type == "hash" and not self.is_valid_hash(indicator):
            return "Invalid hash format."
        elif indicator_type == "ip" and not self.is_valid_ip(indicator):
            return "Invalid IP format."
        elif indicator_type == "email" and not self.is_valid_email(indicator):
            return "Invalid email format."
        elif indicator_type == "domain" and not self.is_valid_domain(indicator):
            return "Invalid domain format."
        elif indicator_type == "url" and not self.is_valid_url(indicator):
            return "Invalid URL format."
        elif indicator_type not in ["hash", "ip", "email", "domain", "url"]:
            return "Invalid indicator type."
        return None

    def is_valid_hash(self, indicator):
        # Example hash regex (MD5, SHA1, SHA256)
        hash_regex = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
        return bool(hash_regex.match(indicator))

    def is_valid_ip(self, indicator):
        # Validate IPv4 or IPv6 addresses
        ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
        return bool(ip_regex.match(indicator))

    def is_valid_email(self, indicator):
        # Validate email format
        email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(email_regex.match(indicator))

    def is_valid_domain(self, indicator):
        # Validate domain format (basic check)
        domain_regex = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(domain_regex.match(indicator))

    def is_valid_url(self, indicator):
        # Validate URL format
        url_regex = re.compile(r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(url_regex.match(indicator))

class SearchQueryHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        search_queries = SearchQuery.objects.filter(user=request.user)
        serializer = SearchQuerySerializer(search_queries, many=True)
        return Response(serializer.data)

class ModuleListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        modules = Module.objects.all()
        serializer = ModuleSerializer(modules, many=True)
        return Response(serializer.data)

class UserModuleToggleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        module_id = request.data.get('module_id')
        enabled = request.data.get('enabled')

        if not module_id or enabled is None:
            return Response({"detail": "Module ID and enabled status are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            module = Module.objects.get(id=module_id)
        except Module.DoesNotExist:
            return Response({"detail": "Module not found."}, status=status.HTTP_404_NOT_FOUND)

        user_module, created = UserModule.objects.get_or_create(user=request.user, module=module)
        user_module.enabled = enabled
        user_module.save()

        return Response(UserModuleSerializer(user_module).data, status=status.HTTP_200_OK)

class UserModuleSettingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        modules = Module.objects.all()
        user_modules = {um.module_id: um for um in UserModule.objects.filter(user=request.user)}
        response_data = []
        
        for module in modules:
            user_module = user_modules.get(module.id)

            # Get the current weight, default to module's default weight if not set
            weight = user_module.weight if user_module and hasattr(user_module, 'weight') else module.default_weight

            response_data.append({
                "moduleName": module.name,
                "enabled": user_module.enabled if user_module else False,
                "apiKey": getattr(user_module, "api_key", None) if user_module else None,
                "apiSecret": getattr(user_module, "api_secret", None) if user_module else None,
                "weight": weight  # Add the weight to the response data
            })
        
        return Response(response_data, status=200)
        

    def post(self, request):
        modules_data = request.data
        if not isinstance(modules_data, list):
            return Response({"detail": "Expected a list of module settings."}, status=400)

        for module_data in modules_data:
            module_name = module_data.get("moduleName")
            enabled = module_data.get("enabled", False)
            api_key = module_data.get("apiKey", None)
            api_secret = module_data.get("apiSecret", None)
            weight = module_data.get("weight", None)  # Get the weight from the request

            try:
                module = Module.objects.get(name=module_name)
                
                # Update or create the UserModule instance for the user
                user_module, created = UserModule.objects.get_or_create(user=request.user, module=module)
                user_module.enabled = enabled
                if hasattr(user_module, "api_key"):
                    user_module.api_key = api_key
                if hasattr(user_module, "api_secret"):
                    user_module.api_secret = api_secret
                if weight is not None:  # If weight is provided, update it
                    user_module.weight = weight

                user_module.save()
            except Module.DoesNotExist:
                continue  # Skip invalid modules

        return Response({"detail": "Settings saved."}, status=200)
