from django.urls import path
from .views import SearchQueryView, SearchQueryHistoryView, ModuleListView, UserModuleToggleView, UserModuleSettingsView


urlpatterns = [
    path('search/', SearchQueryView.as_view(), name='search-query'),  # POST to create a search query
    path('history/', SearchQueryHistoryView.as_view(), name='search-history'),  # GET to view search query history
    path('modules/', ModuleListView.as_view(), name='module-list'),  # GET to list all available modules
    path('modules/toggle/', UserModuleToggleView.as_view(), name='toggle-module'),  # POST to enable/disable a module for the user
    path('modules/settings/', UserModuleSettingsView.as_view(), name='module-settings'),  # GET/POST for managing user module settings
]
