
import os
import json
import logging
from django.shortcuts import redirect
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import base64

logger = logging.getLogger(__name__)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

class GmailAuth:
    @staticmethod
    def get_credentials(request):
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

    @staticmethod
    def get_service(credentials):
        return build('gmail', 'v1', credentials=credentials)

class BaseGmailView(View):
    """Base class for Gmail views"""
    
    def dispatch(self, request, *args, **kwargs):
        self.credentials = GmailAuth.get_credentials(request)
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

class GmailAuthView(View):
    """Handle Gmail OAuth flow"""
    
    def get(self, request):
        return_to = request.GET.get('next', '/gmail/list/')
        request.session['return_to'] = return_to
        
        flow = Flow.from_client_secrets_file(
            settings.GOOGLE_CLIENT_SECRETS_FILE,
            scopes=settings.GOOGLE_SCOPES,  # Make sure to use GOOGLE_SCOPES consistently
            redirect_uri=settings.GMAIL_REDIRECT_URI
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        request.session['state'] = state
        return redirect(authorization_url)

class GmailCallbackView(View):
    """Handle OAuth callback"""
    
    def get(self, request):
        try:
            state = request.session['state']
            flow = Flow.from_client_secrets_file(
                settings.GOOGLE_CLIENT_SECRETS_FILE,
                scopes=settings.GOOGLE_SCOPES,  # Make sure to use GOOGLE_SCOPES consistently
                state=state,
                redirect_uri=settings.GMAIL_REDIRECT_URI
            )
            
            authorization_response = request.build_absolute_uri()
            flow.fetch_token(authorization_response=authorization_response)
            
            credentials = flow.credentials
            request.session['credentials'] = credentials.to_json()
            
            return_to = request.session.get('return_to', '/gmail/list/')
            request.session.pop('state', None)
            request.session.pop('return_to', None)
            
            return redirect(return_to)
            
        except Exception as e:
            logger.error(f"Callback error: {str(e)}")
            return JsonResponse({
                'error': f'Authentication failed: {str(e)}',
                'redirect_url': '/gmail/auth/'
            }, status=500)

class GmailListMessagesView(View):
    """Handle listing emails"""
    
    def get(self, request):
        try:
            # Get credentials from session
            if 'credentials' not in request.session:
                return redirect('/gmail/auth/')
                
            creds_info = json.loads(request.session['credentials'])
            credentials = Credentials.from_authorized_user_info(creds_info)
            
            if not credentials.valid:
                if credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                    request.session['credentials'] = credentials.to_json()
                else:
                    return redirect('/gmail/auth/')
            
            # Build Gmail service
            service = build('gmail', 'v1', credentials=credentials)
            
            # Get query parameters
            q = request.GET.get('q', '')
            max_results = int(request.GET.get('max_results', 10))
            page_token = request.GET.get('page_token', None)
            
            # List messages
            results = service.users().messages().list(
                userId='me',
                q=q,
                maxResults=max_results,
                pageToken=page_token
            ).execute()
            
            messages = results.get('messages', [])
            next_page_token = results.get('nextPageToken')
            
            # Get full message details
            detailed_messages = []
            for msg in messages:
                message_detail = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='full'
                ).execute()
                
                headers = message_detail['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                from_email = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'Unknown')
                
                detailed_messages.append({
                    'id': msg['id'],
                    'subject': subject,
                    'from': from_email,
                    'date': date,
                    'snippet': message_detail.get('snippet', ''),
                })
            
            return JsonResponse({
                'messages': detailed_messages,
                'next_page_token': next_page_token
            })
            
        except Exception as e:
            logger.error(f"Error listing messages: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class GmailMessageDetailView(BaseGmailView):
    """Handle individual email operations"""
    
    def get(self, request, message_id):
        try:
            service = GmailAuth.get_service(self.credentials)
            
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            headers = message['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
            from_email = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown')
            date = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'Unknown')
            
            # Process message parts
            parts = []
            attachments = []
            
            def process_parts(payload):
                if 'parts' in payload:
                    for part in payload['parts']:
                        if part['mimeType'].startswith('text'):
                            if 'data' in part['body']:
                                text = base64.urlsafe_b64decode(part['body']['data']).decode()
                                parts.append({
                                    'mimeType': part['mimeType'],
                                    'text': text
                                })
                        elif 'attachmentId' in part.get('body', {}):
                            attachments.append({
                                'id': part['body']['attachmentId'],
                                'filename': part.get('filename', 'unnamed'),
                                'mimeType': part['mimeType'],
                                'size': part['body'].get('size', 0)
                            })
                        process_parts(part)
                elif payload['mimeType'].startswith('text'):
                    if 'data' in payload['body']:
                        text = base64.urlsafe_b64decode(payload['body']['data']).decode()
                        parts.append({
                            'mimeType': payload['mimeType'],
                            'text': text
                        })
            
            process_parts(message['payload'])
            
            return JsonResponse({
                'id': message_id,
                'subject': subject,
                'from': from_email,
                'date': date,
                'snippet': message.get('snippet', ''),
                'parts': parts,
                'attachments': attachments,
                'user_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"Error getting message details: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class GmailAttachmentView(BaseGmailView):
    """Handle viewing email attachments"""
    
    def get(self, request, message_id, attachment_id):
        try:
            service = GmailAuth.get_service(self.credentials)
            
            attachment = service.users().messages().attachments().get(
                userId='me',
                messageId=message_id,
                id=attachment_id
            ).execute()
            
            file_data = base64.urlsafe_b64decode(attachment['data'])
            
            # Get attachment metadata from the message
            message = service.users().messages().get(
                userId='me',
                id=message_id
            ).execute()
            
            attachment_metadata = None
            for part in message['payload'].get('parts', []):
                if part.get('body', {}).get('attachmentId') == attachment_id:
                    attachment_metadata = part
                    break
            
            if attachment_metadata:
                content_type = attachment_metadata.get('mimeType', 'application/octet-stream')
                filename = attachment_metadata.get('filename', 'attachment')
            else:
                content_type = 'application/octet-stream'
                filename = 'attachment'
            
            response = HttpResponse(file_data, content_type=content_type)
            response['Content-Disposition'] = f'inline; filename="{filename}"'
            return response
            
        except Exception as e:
            logger.error(f"Error viewing attachment: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class GmailAttachmentDownloadView(BaseGmailView):
    """Handle downloading email attachments"""
    
    def get(self, request, message_id, attachment_id):
        try:
            service = GmailAuth.get_service(self.credentials)
            
            # Get the attachment
            attachment = service.users().messages().attachments().get(
                userId='me',
                messageId=message_id,
                id=attachment_id
            ).execute()
            
            file_data = base64.urlsafe_b64decode(attachment['data'])
            
            # Get attachment metadata
            message = service.users().messages().get(
                userId='me',
                id=message_id
            ).execute()
            
            attachment_metadata = None
            for part in message['payload'].get('parts', []):
                if part.get('body', {}).get('attachmentId') == attachment_id:
                    attachment_metadata = part
                    break
            
            if attachment_metadata:
                content_type = attachment_metadata.get('mimeType', 'application/octet-stream')
                filename = attachment_metadata.get('filename', 'attachment')
            else:
                content_type = 'application/octet-stream'
                filename = 'attachment'
            
            response = HttpResponse(file_data, content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
            
        except Exception as e:
            logger.error(f"Error downloading attachment: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class GmailComposeView(BaseGmailView):
    """Handle composing and sending emails"""
    
    def post(self, request):
        try:
            service = GmailAuth.get_service(self.credentials)
            
            data = json.loads(request.body)
            to = data.get('to', '')
            subject = data.get('subject', '')
            body = data.get('body', '')
            
            message = MIMEMultipart()
            message['to'] = to
            message['subject'] = subject
            
            msg = MIMEText(body)
            message.attach(msg)
            
            # Handle attachments if any
            if 'attachments' in request.FILES:
                for attachment in request.FILES.getlist('attachments'):
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {attachment.name}'
                    )
                    message.attach(part)
            
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            
            message = service.users().messages().send(
                userId='me',
                body={'raw': raw}
            ).execute()
            
            return JsonResponse({
                'message': 'Email sent successfully',
                'message_id': message['id'],
                'user_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
