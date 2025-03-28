from django.db import models

class Document(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    nom_document = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    type_document = models.CharField(max_length=100)
    date_creation = models.DateField(auto_now_add=True)
    date_modification = models.DateField(auto_now=True)

    def __str__(self):
        return self.nom_document


