from django.contrib import admin
from django.urls import path,include
from .import views
urlpatterns = [
path('document/',views.DocumentAddView.as_view()),
path('document-Add/',views.DocumentAddView.as_view()), 
path('document/<int:id>/',views.DocumentDetailView.as_view()) ,
path('document-update/<int:id>/',views.DocumentUpdateView.as_view()), 
path('document-Delete/<int:id>/',views.DocumentDeleteView.as_view())   
]