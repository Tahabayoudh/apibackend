from django.urls import path
from . import views

urlpatterns = [
    path('auth/', views.DriveAuthView.as_view(), name='google_drive_auth'),
    path('oauth2callback/', views.DriveCallbackView.as_view(), name='google_drive_callback'),
    path('list/', views.DriveListFilesView.as_view(), name='list_drive_files'),
    path('file/<str:file_id>/', views.DriveFileDetailView.as_view(), name='file_detail'),
    path('create/', views.DriveFileCreateView.as_view(), name='create_file'),
    path('update/<str:file_id>/', views.DriveFileUpdateView.as_view(), name='update_file'),
    path('delete/<str:file_id>/', views.DriveFileDeleteView.as_view(), name='delete_file'),
    path('download/<str:file_id>/', views.DriveDownloadView.as_view(), name='download_file'),
        path('upload/document/', views.DriveDocumentUploadView.as_view(), name='drive-document-upload'),
   path('upload/', views.UploadToDriveView.as_view(), name='upload_photo'),

]