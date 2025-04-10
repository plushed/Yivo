from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import SearchQuery, Module
from .serializers import SearchQuerySerializer
from rest_framework.permissions import IsAuthenticated
from .serializers import ModuleSerializer

class SearchQueryView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        indicator = request.data.get('indicator')
        indicator_type = request.data.get('indicator_type')

        if not indicator or not indicator_type:
            return Response({"detail": "Indicator and indicator_type are required."}, status=400)

        # Get the list of enabled modules for the user
        user_modules = UserModule.objects.filter(user=request.user, enabled=True)
        modules = [user_module.module for user_module in user_modules]

        # Filter modules based on the indicator type from the request
        applicable_modules = [module for module in modules if indicator_type in module.indicator_types]

        results = []
        for module in applicable_modules:
            # Use the dispatch table to get the corresponding query class
            query_class = MODULE_QUERIES.get(module.module_type)

            if query_class:
                query_instance = query_class()
                results.append(query_instance.query(indicator))
            else:
                results.append({"error": f"No handler for module type {module.module_type}"})

        return Response({"results": results}, status=200)

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