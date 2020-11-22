"""vcs_django URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.views.generic.base import TemplateView
from backend import views

urlpatterns = [
    path('admin', admin.site.urls),
    path('', TemplateView.as_view(template_name="index.html")),
    path('test', views.test),
    path('getBaseInfo', views.get_base_info),
    path('getBaseInfoTimeSeries', views.get_base_info_time_series),
    path('getECSGroup', views.get_ECS_group),
    path('getECSGroupByTime', views.get_ECS_group_by_time),
    # path('getAllESCByRegion/', views.get_all_ESC_by_Region),
    # path('getbadFileByEeleECS/', views.get_bad_file_by_ECS)
]
