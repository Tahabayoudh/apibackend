from django.shortcuts import redirect
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError


#test mt3i l code
from google.oauth2 import service_account

from io import BytesIO
import os
import json
import logging

logger = logging.getLogger(__name__)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

class GoogleDriveAuth:
    
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
        return build('drive', 'v3', credentials=credentials)
class DriveAuthView(View):
    """Handle Google Drive OAuth flow"""
    
    def get(self, request):
        # Store the return URL if provided
        return_to = request.GET.get('next', '/drive/list/')
        request.session['return_to'] = return_to
        
        flow = Flow.from_client_secrets_file(
            settings.GOOGLE_CLIENT_SECRETS_FILE,
            scopes=settings.GOOGLE_SCOPES,
            redirect_uri=settings.DRIVE_REDIRECT_URI
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        request.session['state'] = state
        return redirect(authorization_url)
class DriveCallbackView(View):
    """Handle OAuth callback"""
    
    def get(self, request):
        if 'state' not in request.session:
            return JsonResponse({'error': 'No state in session'}, status=400)
        
        try:
            state = request.session['state']
            flow = Flow.from_client_secrets_file(
                settings.GOOGLE_CLIENT_SECRETS_FILE,
                scopes=settings.GOOGLE_SCOPES,
                state=state,
                redirect_uri=settings.DRIVE_REDIRECT_URI
            )
            
            # Get the authorization code from the callback
            authorization_response = request.build_absolute_uri()
            flow.fetch_token(authorization_response=authorization_response)
            
            # Store credentials in session
            credentials = flow.credentials
            request.session['credentials'] = credentials.to_json()
            
            # Get the return URL from session or default to list view
            return_to = request.session.get('return_to', '/drive/list/')
            
            # Clear session data we don't need anymore
            request.session.pop('state', None)
            request.session.pop('return_to', None)
            
            return redirect(return_to)
            
        except Exception as e:
            logger.error(f"Callback error: {str(e)}")
            return JsonResponse({
                'error': f'Authentication failed: {str(e)}',
                'redirect_url': '/drive/auth/'
            }, status=500)
class BaseGoogleDriveView(View):
    """Base class for Google Drive views"""
    
    def dispatch(self, request, *args, **kwargs):
        self.credentials = GoogleDriveAuth.get_credentials(request)
        if not self.credentials:
            return redirect('/drive/auth/')
        
        try:
            service = build('oauth2', 'v2', credentials=self.credentials)
            user_info = service.userinfo().get().execute()
            self.user_email = user_info.get('email')
        except Exception as e:
            logger.error(f"Error getting user email: {str(e)}")
            self.user_email = None
            
        return super().dispatch(request, *args, **kwargs)

@method_decorator(csrf_exempt, name='dispatch')
class DriveListFilesView(BaseGoogleDriveView):
    """Handle listing files"""
    
    def get(self, request):
        try:
            service = GoogleDriveAuth.get_service(self.credentials)
            query = f"'me' in owners or '{self.user_email}' in writers"
            results = service.files().list(
                pageSize=10,
                fields="files(id, name, mimeType, createdTime, owners, shared)",
                q=query
            ).execute()
            
            files = results.get('files', [])
            for file in files:
                file['user_email'] = self.user_email
                file['is_owner'] = any(owner.get('emailAddress') == self.user_email 
                                     for owner in file.get('owners', []))
            
            return JsonResponse({
                'files': files,
                'user_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"File listing error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class DriveFileDetailView(BaseGoogleDriveView):
    """Handle getting file details"""
    
    def get(self, request, file_id):
        try:
            service = GoogleDriveAuth.get_service(self.credentials)
            file = service.files().get(
                fileId=file_id,
                fields='id, name, mimeType, createdTime, owners, webViewLink, webContentLink'
            ).execute()
            
            response_data = {
                **file,
                'user_email': self.user_email,
                'is_owner': any(owner.get('emailAddress') == self.user_email 
                              for owner in file.get('owners', [])),
                'view_url': file.get('webViewLink'),
                'download_url': file.get('webContentLink')
            }
            return JsonResponse(response_data)
            
            
        except Exception as e:
            logger.error(f"File detail error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class DriveFileCreateView(BaseGoogleDriveView):
    """Handle file creation"""
    
    def post(self, request):
        try:
            service = GoogleDriveAuth.get_service(self.credentials)
            
            file_metadata = {
                'name': request.POST.get('name', 'Untitled'),
                'mimeType': request.POST.get('mimeType', 'application/vnd.google-apps.document')
            }
            
            share_with = request.POST.getlist('share_with', [])
            
            if 'file' in request.FILES:
                media = MediaFileUpload(
                    request.FILES['file'],
                    mimetype=request.FILES['file'].content_type,
                    resumable=True
                )
                file = service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute()
            else:
                file = service.files().create(
                    body=file_metadata,
                    fields='id'
                ).execute()
            
            for email in share_with:
                permission = {
                    'type': 'user',
                    'role': 'writer',
                    'emailAddress': email
                }
                service.permissions().create(
                    fileId=file.get('id'),
                    body=permission,
                    sendNotificationEmail=True
                ).execute()
            
            return JsonResponse({
                'message': 'File created successfully',
                'file_id': file.get('id'),
                'shared_with': share_with,
                'owner_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"File creation error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
@method_decorator(csrf_exempt, name='dispatch')
class DriveFileUpdateView(BaseGoogleDriveView):
    """Handle file updates"""
    
    def get(self, request, file_id):
        """Get file update form"""
        try:
            service = GoogleDriveAuth.get_service(self.credentials)
            file = service.files().get(
                fileId=file_id,
                fields='id, name, mimeType, createdTime, owners'
            ).execute()
            
            # Check ownership
            if not any(owner.get('emailAddress') == self.user_email 
                      for owner in file.get('owners', [])):
                return JsonResponse(
                    {'error': 'You do not have permission to modify this file'}, 
                    status=403
                )
            
            # Get current sharing settings
            permissions = service.permissions().list(
                fileId=file_id,
                fields='permissions(id,emailAddress,role)'
            ).execute()
            
            response_data = {
                **file,
                'user_email': self.user_email,
                'permissions': permissions.get('permissions', [])
            }
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"File update form error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    
    def put(self, request, file_id):
        """Update file"""
        try:
            service = GoogleDriveAuth.get_service(self.credentials)
            data = json.loads(request.body)
            
            # Check ownership
            file = service.files().get(
                fileId=file_id, 
                fields='owners'
            ).execute()
            
            if not any(owner.get('emailAddress') == self.user_email 
                      for owner in file.get('owners', [])):
                return JsonResponse(
                    {'error': 'You do not have permission to modify this file'}, 
                    status=403
                )
            
            # Update file metadata
            file_metadata = {
                'name': data.get('name'),
                'description': data.get('description', '')
            }
            
            # Update sharing settings
            share_updates = data.get('share_updates', [])
            for update in share_updates:
                permission = {
                    'type': 'user',
                    'role': update.get('role', 'reader'),
                    'emailAddress': update.get('email')
                }
                service.permissions().create(
                    fileId=file_id,
                    body=permission,
                    sendNotificationEmail=True
                ).execute()
            
            # Remove permissions if specified
            remove_permissions = data.get('remove_permissions', [])
            for email in remove_permissions:
                # Find and delete permission by email
                permissions = service.permissions().list(
                    fileId=file_id,
                    fields='permissions(id,emailAddress)'
                ).execute()
                
                for perm in permissions.get('permissions', []):
                    if perm.get('emailAddress') == email:
                        service.permissions().delete(
                            fileId=file_id,
                            permissionId=perm['id']
                        ).execute()
            
            # Update file
            updated_file = service.files().update(
                fileId=file_id,
                body=file_metadata,
                fields='id, name, mimeType, createdTime, owners'
            ).execute()
            
            return JsonResponse({
                'message': 'File updated successfully',
                'file': updated_file,
                'owner_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"File update error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
@method_decorator(csrf_exempt, name='dispatch')
class DriveFileDeleteView(BaseGoogleDriveView):
    """Handle file deletion"""
    
    def delete(self, request, file_id):
        try:
            service = GoogleDriveAuth.get_service(self.credentials)
            
            file = service.files().get(
                fileId=file_id, 
                fields='owners'
            ).execute()
            
            if not any(owner.get('emailAddress') == self.user_email 
                      for owner in file.get('owners', [])):
                return JsonResponse(
                    {'error': 'You do not have permission to delete this file'}, 
                    status=403
                )
            
            service.files().delete(fileId=file_id).execute()
            return JsonResponse({
                'message': 'File deleted successfully',
                'owner_email': self.user_email
            })
            
        except Exception as e:
            logger.error(f"File deletion error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
class DriveDownloadView(View):
    """Handle file downloads"""
    
    def get(self, request, file_id):
        credentials = GoogleDriveAuth.get_credentials(request)
        if not credentials:
            return redirect('/drive/auth/')
            
        try:
            service = GoogleDriveAuth.get_service(credentials)
            
            # Get file metadata
            file = service.files().get(fileId=file_id).execute()
            file_name = file.get('name', 'downloaded_file')
            
            # Download file content
            request = service.files().get_media(fileId=file_id)
            fh = BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            
            done = False
            while done is False:
                status, done = downloader.next_chunk()
            
            # Prepare response
            fh.seek(0)
            response = HttpResponse(fh.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            
            return response
            
        except Exception as e:
            logger.error(f"Download error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
@method_decorator(csrf_exempt, name='dispatch')
class DriveDocumentUploadView(BaseGoogleDriveView):
    """Handle document upload to Google Drive"""
    
    def _get_or_create_folder(self, service, folder_name="APIAutome Documents"):
        """Get or create upload folder"""
        try:
            # Search for existing folder
            results = service.files().list(
                q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and 'me' in owners",
                fields="files(id, name)"
            ).execute()
            
            files = results.get('files', [])
            
            # Return existing folder if found
            if files:
                return files[0]['id']
            
            # Create new folder if not found
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            folder = service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            return folder.get('id')
            
        except Exception as e:
            logger.error(f"Folder creation error: {str(e)}")
            return None

    def post(self, request):
        # Store return path for after authentication
        request.session['return_to'] = request.path
        
        # Check if credentials are valid
        if not self.credentials:
            return JsonResponse({
                'error': 'Authentication required',
                'redirect_url': '/drive/auth/'
            }, status=401)

        try:
            service = GoogleDriveAuth.get_service(self.credentials)
            
            # Get or create destination folder
            folder_id = self._get_or_create_folder(service)
            if not folder_id:
                return JsonResponse({
                    'error': 'Could not create or find destination folder'
                }, status=500)
            
            if 'document' not in request.FILES:
                return JsonResponse({
                    'error': 'No document provided'
                }, status=400)
            
            document = request.FILES['document']
            
            # Verify document type
            allowed_mimetypes = [
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/pdf',
                'text/plain'
            ]
            
            if document.content_type not in allowed_mimetypes:
                return JsonResponse({
                    'error': 'Invalid document type. Only Word, PDF, and text documents are allowed.',
                    'allowed_types': allowed_mimetypes
                }, status=400)
            
            # Prepare file metadata
            file_metadata = {
                'name': document.name,
                'mimeType': document.content_type,
                'parents': [folder_id]  # Place in specific folder
            }
            
            # Create file in memory buffer
            file_content = BytesIO(document.read())
            
            # Prepare media
            media = MediaFileUpload(
                BytesIO(file_content.getvalue()),
                mimetype=document.content_type,
                resumable=True
            )
            
            # Create file on Google Drive
            file = service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, name, webViewLink, mimeType, parents',
            ).execute()
            
            return JsonResponse({
                'message': 'Document uploaded successfully',
                'file_id': file.get('id'),
                'file_name': file.get('name'),
                'view_link': file.get('webViewLink'),
                'mime_type': file.get('mimeType'),
                'folder_id': folder_id,
                'owner_email': self.user_email
            })
            
        except HttpError as e:
            logger.error(f"Google API error: {str(e)}")
            return JsonResponse({
                'error': 'Google Drive API error',
                'details': str(e)
            }, status=500)
            
        except Exception as e:
            logger.error(f"Document upload error: {str(e)}")
            return JsonResponse({
                'error': 'Upload failed',
                'details': str(e)
            }, status=500)

    def get(self, request):
        """Handle GET requests - show upload information"""
        if not self.credentials:
            return JsonResponse({
                'error': 'Authentication required',
                'redirect_url': '/drive/auth/'
            }, status=401)
            
        return JsonResponse({
            'message': 'Please POST a document to upload',
            'allowed_types': [
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/pdf',
                'text/plain'
            ],
            'max_size': '10MB',
            'upload_url': request.build_absolute_uri(),
            'user_email': self.user_email
        })
    



SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE =  os.path.join(os.path.dirname(__file__), 'client_secret2.json')
PARENT_FOLDER_ID = '1PZ_gUrZx7PiirmgnrFoFRbrKg_5XT-aI'  # Remplace par l'ID de ton dossier Google Drive


def authenticate():
    """Authenticate using service account"""
    try:
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE,
            scopes=SCOPES
        )
        return credentials
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return None



class UploadToDriveView(View):
    def get(self, request):
        folder_id = "1PZ_gUrZx7PiirmgnrFoFRbrKg_5XT-aI"  # Remplace par ton Folder ID
        self.credentials = GoogleDriveAuth.get_credentials(request)
        if not self.credentials:
            return redirect('/drive/auth/')
        try:
            service = build("drive", "v3", credentials=self.credentials )

            file_metadata = {"name": "photo2.jpg", "parents": [folder_id]}
            media = MediaFileUpload("./drive/res5.png", mimetype="image/jpeg", resumable=True)

            file = service.files().create(
                body=file_metadata,
                media_body=media,
                fields="id"
            ).execute()

            return JsonResponse({"file_id": file.get("id")})

        except HttpError as error:
            print(f"An error occurred: {error}")
            return JsonResponse({"error": str(error)}, status=500)
