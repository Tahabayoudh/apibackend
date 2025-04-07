from django.urls import path
from .views import (
    DriveAuthView,
    DriveCallbackView,
    DriveListFilesView,
    DriveFileDetailView,
    DriveFileCreateView,
    DriveFileUpdateView,
    DriveFileDeleteView,
    DriveDownloadView,
    UploadToDriveView,
    UploadToFolderView  # Add this new import
)

urlpatterns = [
    # Authentication URLs
    path('auth/', DriveAuthView.as_view(), name='google_drive_auth'),
    path('oauth2callback/', DriveCallbackView.as_view(), name='google_drive_callback'),
    
    # File management URLs
    path('list/', DriveListFilesView.as_view(), name='list_drive_files'),
    path('file/<str:file_id>/', DriveFileDetailView.as_view(), name='file_detail'),
    path('create/', DriveFileCreateView.as_view(), name='create_file'),
    path('update/<str:file_id>/', DriveFileUpdateView.as_view(), name='update_file'),
    path('delete/<str:file_id>/', DriveFileDeleteView.as_view(), name='delete_file'),
    path('download/<str:file_id>/', DriveDownloadView.as_view(), name='download_file'),
    path('upload/', UploadToDriveView.as_view(), name='upload_file'),
    # Add new URL for folder upload
    path('upload-to-folder/', UploadToFolderView.as_view(), name='upload_to_folder'),
]
