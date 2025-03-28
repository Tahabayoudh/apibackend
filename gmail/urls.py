from django.urls import path
from .views import GmailListMessagesView, GmailMessageDetailView,GmailAttachmentView,GmailAttachmentDownloadView

urlpatterns = [
    path('messages/', GmailListMessagesView.as_view(), name='gmail-messages'),
    path('messages/<str:message_id>/', GmailMessageDetailView.as_view(), name='gmail-message-detail'),
     path('messages/<str:message_id>/attachments/<str:attachment_id>/view/', GmailAttachmentView.as_view(), name='gmail-attachment-view'),
    path('messages/<str:message_id>/attachments/<str:attachment_id>/download/', GmailAttachmentDownloadView.as_view(), name='gmail-attachment-download'),

]
