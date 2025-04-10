from rest_framework import serializers
from .models import SearchQuery, Module, UserModule

class ModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Module
        fields = ['id', 'name', 'description', 'enabled']

class UserModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModule
        fields = ['id', 'user', 'module', 'enabled']
        
class SearchQuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = SearchQuery
        fields = '__all__'