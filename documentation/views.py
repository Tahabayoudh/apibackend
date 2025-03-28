from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Document
from rest_framework import status
from .serializers import DocumentSerializer
# Create your views here.
class DocumentAddView (APIView):
    def post(self, request, *args, **kwargs):
        serializer = DocumentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class DocumentView (APIView):
    def get(self, request, *args, **kwargs):
        documents = Document.objects.all()
        serializer = DocumentSerializer(documents, many=True)
        return Response(serializer.data)
class DocumentDetailView (APIView):
     def get(self, request, *args, **kwargs):
        id = kwargs.get('id')
        document = Document.objects.get(id=id)
        serializer = DocumentSerializer(document)
        return Response(serializer.data)
class DocumentUpdateView (APIView):
            def put(self, request, *args, **kwargs):
                id = kwargs.get('id')
                document = Document.objects.get(id=id)
                serializer = DocumentSerializer(document, data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            def patch(self, request, *args, **kwargs):
                id = kwargs.get('id')
                document = Document.objects.get(id=id)
                serializer = DocumentSerializer(document, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class DocumentDeleteView (APIView):
            def delete(self, request, *args, **kwargs):
                id = kwargs.get('id')
                document = Document.objects.get(id=id)
                document.delete()
                return Response(status=status.HTTP_204_NO_CONTENT)