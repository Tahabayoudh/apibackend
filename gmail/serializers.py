from rest_framework import serializers
from .models import Email

class EmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Email
        fields = [
            'id', 
            'adresse', 
            'objet', 
            'piece_jointe', 
            'nom_utilisateur',
            'date_creation', 
            'date_modification'
        ]
        read_only_fields = ['date_creation', 'date_modification', 'nom_utilisateur']