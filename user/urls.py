from django.urls import path
from .views import FindUserByauthToken, UserAddView
from .views import UserListView
from .views import UserDetailView
from .views import UserUpdateView
from .views import UserDeleteView
urlpatterns = [
    path('user-add/', UserAddView.as_view()),
    path('user-list/', UserListView.as_view()),
    path('user-detail/<int:pk>/',   UserDetailView.as_view()),
    path('user-update/<int:pk>/',   UserUpdateView.as_view()),
    path('user-delete/<int:pk>/',     UserDeleteView.as_view()),
    path('find-user-by-auth-token/', FindUserByauthToken.as_view()),
]