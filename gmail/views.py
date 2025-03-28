

from django.shortcuts import redirect
from django.http import JsonResponse, FileResponse, HttpResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import json
import base64
import logging
import mimetypes
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# Initialize logger
logger = logging.getLogger(__name__)


class BaseGmailView(View):
    """Base class for Gmail views"""
    
    def dispatch(self, request, *args, **kwargs):
        self.credentials = self.get_credentials(request)
        if not self.credentials:
            return redirect('/gmail/auth/')
        
        try:
            service = build('oauth2', 'v2', credentials=self.credentials)
            user_info = service.userinfo().get().execute()
            self.user_email = user_info.get('email')
        except Exception as e:
            logger.error(f"Error getting user email: {str(e)}")
            self.user_email = None
            
        return super().dispatch(request, *args, **kwargs)
    
    def get_credentials(self, request):
        if 'credentials' not in request.session:
            return None
            
        try:
            creds_info = json.loads(request.session['credentials'])
            creds = Credentials.from_authorized_user_info(creds_info)
            
            if not creds.valid:
                if creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    request.session['credentials'] = creds.to_json()
                else:
                    return None
                    
            return creds
        except Exception as e:
            logger.error(f"Error getting credentials: {str(e)}")
            return None

@method_decorator(csrf_exempt, name='dispatch')
class GmailListMessagesView(BaseGmailView):
    """Handle listing emails"""
    
    def get(self, request):
        try:
            service = build('gmail', 'v1', credentials=self.credentials)
            
            results = service.users().messages().list(
                userId='me',
                maxResults=10,
                labelIds=['INBOX']
            ).execute()
            
            messages = []
            for msg in results.get('messages', []):
                message = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='metadata',
                    metadataHeaders=['From', 'Subject', 'Date']
                ).execute()
                
                headers = message['payload']['headers']
                email_data = {
                    'id': message['id'],
                    'from': next(
                        (header['value'] for header in headers if header['name'] == 'From'),
                        'Unknown'
                    ),
                    'subject': next(
                        (header['value'] for header in headers if header['name'] == 'Subject'),
                        'No Subject'
                    ),
                    'date': next(
                        (header['value'] for header in headers if header['name'] == 'Date'),
                        'No Date'
                    ),
                    'snippet': message.get('snippet', ''),
                }
                messages.append(email_data)
            
            return JsonResponse({
                'messages': messages,
                'user_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"Email listing error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class GmailMessageDetailView(BaseGmailView):
    """Handle getting email details"""
    
    def get(self, request, message_id):
        try:
            service = build('gmail', 'v1', credentials=self.credentials)
            
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            headers = message['payload']['headers']
            email_data = {
                'id': message['id'],
                'from': next(
                    (header['value'] for header in headers if header['name'] == 'From'),
                    'Unknown'
                ),
                'to': next(
                    (header['value'] for header in headers if header['name'] == 'To'),
                    'Unknown'
                ),
                'subject': next(
                    (header['value'] for header in headers if header['name'] == 'Subject'),
                    'No Subject'
                ),
                'date': next(
                    (header['value'] for header in headers if header['name'] == 'Date'),
                    'No Date'
                ),
            }
            
            if 'parts' in message['payload']:
                parts = message['payload']['parts']
                body = ''
                attachments = []
                
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        if 'data' in part['body']:
                            body += base64.urlsafe_b64decode(
                                part['body']['data']
                            ).decode('utf-8')
                    elif 'filename' in part and part['filename']:
                        attachments.append({
                            'id': part['body'].get('attachmentId'),
                            'filename': part['filename'],
                            'mimeType': part['mimeType']
                        })
                
                email_data['body'] = body
                email_data['attachments'] = attachments
            else:
                if 'data' in message['payload']['body']:
                    email_data['body'] = base64.urlsafe_b64decode(
                        message['payload']['body']['data']
                    ).decode('utf-8')
                else:
                    email_data['body'] = ''
                email_data['attachments'] = []
            
            return JsonResponse(email_data)
            
        except Exception as e:
            logger.error(f"Email detail error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
@method_decorator(csrf_exempt, name='dispatch')
class GmailAttachmentView(BaseGmailView):
    def get(self, request, message_id, attachment_id):
        try:
            service = build('gmail', 'v1', credentials=self.credentials)
            
            # First get the message to find attachment details
            message = service.users().messages().get(
                userId='me',
                id=message_id
            ).execute()

            # Find the attachment part
            attachment_part = None
            for part in message['payload'].get('parts', []):
                if part.get('body', {}).get('attachmentId') == attachment_id:
                    attachment_part = part
                    break

            if not attachment_part:
                logger.error(f"Attachment {attachment_id} not found in message {message_id}")
                return JsonResponse({"error": "Attachment not found"}, status=404)

            # Get the attachment data
            attachment = service.users().messages().attachments().get(
                userId='me',
                messageId=message_id,
                id=attachment_id
            ).execute()

            if not attachment.get('data'):
                logger.error(f"No data found for attachment {attachment_id}")
                return JsonResponse({"error": "Attachment data not found"}, status=404)

            # Decode the attachment data
            file_data = base64.urlsafe_b64decode(attachment['data'])
            
            content_type = attachment_part.get('mimeType', 'application/octet-stream')
            filename = attachment_part.get('filename', 'attachment')
            
            response = HttpResponse(file_data, content_type=content_type)
            response['Content-Disposition'] = f'inline; filename="{filename}"'
            return response

        except Exception as e:
            logger.error(f"Attachment view error: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class GmailAttachmentDownloadView(BaseGmailView):
    def get(self, request, message_id, attachment_id):
        try:
            service = build('gmail', 'v1', credentials=self.credentials)
            
            # First get the message to find attachment details
            message = service.users().messages().get(
                userId='me',
                id=message_id
            ).execute()

            # Find the attachment part
            attachment_part = None
            for part in message['payload'].get('parts', []):
                if part.get('body', {}).get('attachmentId') == attachment_id:
                    attachment_part = part
                    break

            if not attachment_part:
                logger.error(f"Attachment {attachment_id} not found in message {message_id}")
                return JsonResponse({"error": "Attachment not found"}, status=404)

            # Get the attachment data
            attachment = service.users().messages().attachments().get(
                userId='me',
                messageId=message_id,
                id=attachment_id
            ).execute()

            if not attachment.get('data'):
                logger.error(f"No data found for attachment {attachment_id}")
                return JsonResponse({"error": "Attachment data not found"}, status=404)

            # Decode the attachment data
            file_data = base64.urlsafe_b64decode(attachment['data'])
            
            content_type = attachment_part.get('mimeType', 'application/octet-stream')
            filename = attachment_part.get('filename', 'attachment')
            
            response = HttpResponse(file_data, content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response

        except Exception as e:
            logger.error(f"Attachment download error: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)