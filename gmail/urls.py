from django.urls import path
from .views import (
    GmailAuthView,
    GmailCallbackView,
    GmailListMessagesView,
    GmailMessageDetailView,
    GmailAttachmentView,
    GmailAttachmentDownloadView,
    GmailComposeView
)

urlpatterns = [
    # Authentication URLs
    path('auth/', GmailAuthView.as_view(), name='gmail_auth'),
    path('oauth2callback/', GmailCallbackView.as_view(), name='gmail_callback'),
    
    # Message management URLs
    path('list/', GmailListMessagesView.as_view(), name='gmail-messages'),
    path('detail/<str:message_id>/', GmailMessageDetailView.as_view(), name='gmail-message-detail'),
    path('compose/', GmailComposeView.as_view(), name='gmail-compose'),
    
    # Attachment URLs
    path('view/<str:message_id>/attachments/<str:attachment_id>/view/', 
         GmailAttachmentView.as_view(), 
         name='gmail-attachment-view'),
    path('download/<str:message_id>/attachments/<str:attachment_id>/download/', 
         GmailAttachmentDownloadView.as_view(), 
         name='gmail-attachment-download'),
]
